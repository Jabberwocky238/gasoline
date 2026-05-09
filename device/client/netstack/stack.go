package netstack

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
)

// NIC identifiers. Fixed at construction.
const (
	nicTun     tcpip.NICID = 1
	nicOverlay tcpip.NICID = 2
)

// channelQueueSize bounds each NIC's outbound queue. Packets are drained
// promptly into the OnXxxWrite hook; this value only matters during bursts.
const channelQueueSize = 512

// Stack is a ready-to-start userspace IP stack with two NICs (tun, overlay)
// and a registered TCP/UDP forwarder. Create with New, then Start, then feed
// inbound packets via HandleTunInbound / HandleOverlayInbound.
type Stack struct {
	cfg Config

	ipStack *stack.Stack
	tunEP   *channel.Endpoint
	ovlEP   *channel.Endpoint

	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	started bool
	closed  bool
}

// New constructs the stack but does not spawn any goroutines. Call Start.
func New(cfg Config) (*Stack, error) {
	if !cfg.LocalIP.IsValid() {
		return nil, errors.New("netstack: LocalIP required")
	}
	if cfg.OnTunWrite == nil {
		return nil, errors.New("netstack: OnTunWrite required")
	}
	if cfg.OnOverlayWrite == nil {
		return nil, errors.New("netstack: OnOverlayWrite required")
	}
	if cfg.OnOverlayBypass == nil {
		return nil, errors.New("netstack: OnOverlayBypass required")
	}
	if cfg.Mode == ModeSocks5 && !cfg.Socks5Peer.IsValid() {
		return nil, errors.New("netstack: Mode=Socks5 requires Socks5Peer")
	}

	ipStack := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})

	tunEP := channel.New(channelQueueSize, cfg.mtu(), "")
	ovlEP := channel.New(channelQueueSize, cfg.mtu(), "")

	if err := ipStack.CreateNIC(nicTun, tunEP); err != nil {
		return nil, fmt.Errorf("netstack: CreateNIC(tun): %s", err)
	}
	if err := ipStack.CreateNIC(nicOverlay, ovlEP); err != nil {
		return nil, fmt.Errorf("netstack: CreateNIC(overlay): %s", err)
	}

	// Promiscuous + spoofing on both NICs lets gVisor accept any destination
	// arriving from TUN and emit any source on outbound packets.
	for _, id := range []tcpip.NICID{nicTun, nicOverlay} {
		if err := ipStack.SetPromiscuousMode(id, true); err != nil {
			return nil, fmt.Errorf("netstack: SetPromiscuousMode(%d): %s", id, err)
		}
		if err := ipStack.SetSpoofing(id, true); err != nil {
			return nil, fmt.Errorf("netstack: SetSpoofing(%d): %s", id, err)
		}
	}

	// No AddProtocolAddress on either NIC. Spoofing=true lets DialTCPWithBind
	// bind any source address, and *not* assigning LocalIP anywhere avoids
	// gvisor treating it as a local-delivery target when the stack emits
	// replies back to the app (whose dst is LocalIP).

	// Routing: when operating in SOCKS5 mode add a specific /32 (or /128)
	// route for the SOCKS5 peer → NIC-OVERLAY, so DialTCPWithBind picks
	// NIC-OVERLAY purely from destination lookup and the synthesized SYN
	// lands in ovlEP's outbound queue. Everything else goes out NIC-TUN.
	// In ModeDirect we don't install the peer route — Socks5Peer is ignored.
	routes := []tcpip.Route{}
	if cfg.useSocks5() {
		peerAddr, _ := protoAddress(cfg.Socks5Peer.Addr())
		routes = append(routes, tcpip.Route{
			Destination: peerAddr.WithPrefix().Subnet(),
			NIC:         nicOverlay,
		})
	}
	routes = append(routes,
		tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicTun},
		tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: nicTun},
	)
	ipStack.SetRouteTable(routes)

	// TCP tuning mirrored from sing-tun's gvisor stack defaults.
	sackOpt := tcpip.TCPSACKEnabled(true)
	_ = ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackOpt)
	modOpt := tcpip.TCPModerateReceiveBufferOption(true)
	_ = ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &modOpt)

	ctx, cancel := context.WithCancel(context.Background())
	s := &Stack{
		cfg:     cfg,
		ipStack: ipStack,
		tunEP:   tunEP,
		ovlEP:   ovlEP,
		ctx:     ctx,
		cancel:  cancel,
	}

	// Forwarders: any unmatched TCP/UDP SYN hits these callbacks.
	tcpFwd := tcp.NewForwarder(ipStack, 0, 2048, s.handleTCP)
	ipStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(ipStack, s.handleUDP)
	ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	return s, nil
}

// Start begins draining outbound packets from both NICs into the caller's
// write hooks. It is safe to call once; subsequent calls are no-ops.
func (s *Stack) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("netstack: closed")
	}
	if s.started {
		return nil
	}
	s.started = true
	go s.drainOutbound(s.tunEP, s.cfg.OnTunWrite)
	go s.drainOutbound(s.ovlEP, s.cfg.OnOverlayWrite)
	return nil
}

// Close tears the stack down. Safe to call multiple times.
func (s *Stack) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.cancel()
	s.tunEP.Close()
	s.ovlEP.Close()
	s.ipStack.Close()
	for _, ep := range s.ipStack.CleanupEndpoints() {
		ep.Abort()
	}
	return nil
}

// HandleTunInbound feeds one raw IP packet read from the OS TUN. The caller
// must pass the full IP packet (no link header). Classification happens here:
// overlay-peer dst goes straight to OnOverlayBypass; everything else is
// injected into gVisor NIC-TUN for reassembly.
func (s *Stack) HandleTunInbound(ipPkt []byte) {
	if len(ipPkt) == 0 {
		return
	}
	switch d, _ := s.classifyInbound(ipPkt); d {
	case decisionOverlayBypass:
		if err := s.cfg.OnOverlayBypass(ipPkt); err != nil {
			return
		}
	case decisionStack:
		s.inject(s.tunEP, ipPkt)
	case decisionDrop:
		return
	}
}

// HandleOverlayInbound feeds one raw IP packet received from the overlay
// (ethernet already stripped) whose destination lives inside the stack — for
// example the SYN-ACK of the synthesized SOCKS5 upstream connection.
func (s *Stack) HandleOverlayInbound(ipPkt []byte) {
	if len(ipPkt) == 0 {
		return
	}
	s.inject(s.ovlEP, ipPkt)
}

// inject is the common path for pushing an inbound packet into one of our
// channel endpoints.
func (s *Stack) inject(ep *channel.Endpoint, ipPkt []byte) {
	var proto tcpip.NetworkProtocolNumber
	switch ipPkt[0] >> 4 {
	case 4:
		proto = header.IPv4ProtocolNumber
	case 6:
		proto = header.IPv6ProtocolNumber
	default:
		return
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(ipPkt),
	})
	ep.InjectInbound(proto, pkt)
	pkt.DecRef()
}

// drainOutbound pulls PacketBuffers off a channel endpoint's outbound queue
// (i.e., packets gVisor wants to send out that NIC) and feeds them to the
// caller's raw-IP hook until the stack closes.
func (s *Stack) drainOutbound(ep *channel.Endpoint, sink func([]byte) error) {
	for {
		pkt := ep.ReadContext(s.ctx)
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		pkt.DecRef()
		// Copy out of the gvisor-owned view immediately so we can release the
		// chunk back to the pool before calling into user code. The extra
		// allocation per packet is cheap compared to keeping chunks pinned
		// across a potentially slow transport write.
		raw := view.AsSlice()
		out := make([]byte, len(raw))
		copy(out, raw)
		view.Release()
		if err := sink(out); err != nil {
			// The overlay or TUN writer decides whether to surface the error
			// up to the user. Dropping is the only recourse here.
			_ = err
		}
	}
}

// protoAddress converts a netip.Addr into (tcpip.Address, protocol number).
func protoAddress(a netip.Addr) (tcpip.Address, tcpip.NetworkProtocolNumber) {
	if a.Is4() {
		return tcpip.AddrFrom4(a.As4()), ipv4.ProtocolNumber
	}
	return tcpip.AddrFrom16(a.As16()), ipv6.ProtocolNumber
}
