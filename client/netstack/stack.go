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

	// flows tracks (proto, localPort) pairs belonging to endpoints the stack
	// dialed outward on NIC-OVERLAY. Used by MaybeHandleOverlayInbound to
	// discriminate "return traffic for my synthesized connection" from
	// peer-to-peer transparent traffic that belongs on the OS TUN. Keys are
	// flowKey values; values are unused.
	flows sync.Map

	mu      sync.Mutex
	started bool
	closed  bool
}

// flowKey identifies a stack-owned outbound flow on NIC-OVERLAY. proto is
// the transport number as it appears in the IPv4 Protocol field / IPv6
// Next Header field: 6 for TCP, 17 for UDP.
type flowKey struct {
	proto uint8
	port  uint16
}

// Transport protocol numbers as they appear in IPv4 Protocol / IPv6 Next
// Header. Exported for callers that drive RegisterFlow directly from a
// custom dial path (the adapter package and tests).
const (
	ProtoTCP uint8 = 6
	ProtoUDP uint8 = 17
)

// Internal aliases kept for readability inside the package.
const (
	protoTCP = ProtoTCP
	protoUDP = ProtoUDP
)

// RegisterFlow records that the stack has an active endpoint bound to
// (proto, port) on NIC-OVERLAY. Called automatically by dialSocks5 and
// dialSocks5UDP; exposed so higher-level integrations that introduce their
// own outbound paths can participate in MaybeHandleOverlayInbound routing.
func (s *Stack) RegisterFlow(proto uint8, port uint16) {
	s.flows.Store(flowKey{proto, port}, struct{}{})
}

// UnregisterFlow removes a previously registered (proto, port). Safe to
// call more than once; extra deletes are no-ops.
func (s *Stack) UnregisterFlow(proto uint8, port uint16) {
	s.flows.Delete(flowKey{proto, port})
}

// internal getters/setters retained for readability.
func (s *Stack) registerFlow(proto uint8, port uint16)   { s.RegisterFlow(proto, port) }
func (s *Stack) unregisterFlow(proto uint8, port uint16) { s.UnregisterFlow(proto, port) }

// hasFlow reports whether (proto, port) is currently registered.
func (s *Stack) hasFlow(proto uint8, port uint16) bool {
	_, ok := s.flows.Load(flowKey{proto, port})
	return ok
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

// MaybeHandleOverlayInbound decides on the caller's behalf whether an IP
// packet arriving from the overlay belongs to the stack (a synthesized
// upstream's return traffic) or to a peer-to-peer flow that should be
// delivered straight to the OS TUN.
//
// The gasoline integration uses this at the overlay ingress point:
//
//	if !stack.MaybeHandleOverlayInbound(ipPkt) {
//	    tun.Write(ipPkt) // peer-to-peer transparent
//	}
//
// Returns true if the packet was injected into the stack and MUST NOT be
// forwarded to the OS TUN by the caller. Returns false for anything the
// stack does not own: malformed, non-TCP/UDP, or (proto,dstPort) not in
// the flow table. Callers deliver those to the TUN themselves.
//
// IPv6 extension headers are not unrolled here — gvisor's own outbound
// packets don't emit them, and gasoline's overlay transport would be the
// only thing producing ext-header frames for overlay-return traffic, which
// it does not do today. Should that change, this function should grow a
// header walker.
func (s *Stack) MaybeHandleOverlayInbound(ipPkt []byte) bool {
	proto, dstPort, ok := parseTransportDst(ipPkt)
	if !ok {
		return false
	}
	if !s.hasFlow(proto, dstPort) {
		return false
	}
	s.inject(s.ovlEP, ipPkt)
	return true
}

// parseTransportDst pulls (proto, dst port) out of a raw IPv4 or IPv6
// packet. Returns ok=false for malformed input, non-TCP/UDP, or IPv6 with
// extension headers.
func parseTransportDst(pkt []byte) (proto uint8, dstPort uint16, ok bool) {
	if len(pkt) < 1 {
		return 0, 0, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return 0, 0, false
		}
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl+4 {
			return 0, 0, false
		}
		proto = pkt[9]
		if proto != protoTCP && proto != protoUDP {
			return 0, 0, false
		}
		return proto, uint16(pkt[ihl+2])<<8 | uint16(pkt[ihl+3]), true
	case 6:
		if len(pkt) < 44 {
			return 0, 0, false
		}
		proto = pkt[6] // Next Header
		if proto != protoTCP && proto != protoUDP {
			return 0, 0, false
		}
		return proto, uint16(pkt[42])<<8 | uint16(pkt[43]), true
	}
	return 0, 0, false
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
