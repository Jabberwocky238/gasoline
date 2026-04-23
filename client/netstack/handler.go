package netstack

import (
	"context"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/sagernet/gvisor/pkg/waiter"
)

// handleTCP is the gvisor TCP forwarder callback. It's invoked for every SYN
// that doesn't match an active endpoint — i.e. new TCP flows coming from the
// apps via NIC-TUN. We accept, classify by the original destination, and
// splice to the chosen upstream.
func (s *Stack) handleTCP(req *tcp.ForwarderRequest) {
	id := req.ID()
	dst := addrFromTcpip(id.LocalAddress)
	dstPort := id.LocalPort

	decision := s.classifyDial(dst)
	if decision == dialDrop {
		req.Complete(true) // send RST
		return
	}

	var wq waiter.Queue
	ep, terr := req.CreateEndpoint(&wq)
	if terr != nil {
		req.Complete(true)
		return
	}
	req.Complete(false)
	downstream := gonet.NewTCPConn(&wq, ep)

	go s.proxyTCP(downstream, netip.AddrPortFrom(dst, dstPort), decision)
}

// proxyTCP dials the chosen upstream, does the SOCKS5 handshake if needed,
// and bidirectionally copies bytes.
func (s *Stack) proxyTCP(downstream *gonet.TCPConn, target netip.AddrPort, decision dialDecision) {
	defer downstream.Close()

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	var upstream net.Conn
	var err error

	switch decision {
	case dialSocks5:
		upstream, err = s.dialSocks5(ctx, target)
	case dialPhysical:
		upstream, err = s.cfg.PhysicalDialer.DialContext(ctx, "tcp", target.String())
	}
	cancel()
	if err != nil {
		return
	}
	defer upstream.Close()

	splice(downstream, upstream)
}

// handleUDP is the gvisor UDP forwarder callback. Each (src,dst) quadruple
// here corresponds to one logical UDP "flow" in userspace — gvisor dispatches
// packets on existing endpoints automatically; we only see the first one.
func (s *Stack) handleUDP(req *udp.ForwarderRequest) bool {
	id := req.ID()
	dst := addrFromTcpip(id.LocalAddress)
	dstPort := id.LocalPort

	decision := s.classifyDial(dst)
	if decision != dialPhysical {
		// SOCKS5 UDP ASSOCIATE across the overlay is not implemented yet;
		// drop rather than leak. Future work: either add a mux channel on the
		// overlay transport or run SOCKS5 ASSOCIATE over gonet.UDPConn.
		return true
	}
	if s.cfg.PhysicalDialer == nil {
		return true
	}

	var wq waiter.Queue
	ep, terr := req.CreateEndpoint(&wq)
	if terr != nil {
		return true
	}
	downstream := gonet.NewUDPConn(&wq, ep)

	go s.proxyUDP(downstream, netip.AddrPortFrom(dst, dstPort))
	return true
}

// proxyUDP shuttles datagrams between an accepted gonet.UDPConn and a
// physical-NIC-bound PacketConn for as long as traffic flows.
func (s *Stack) proxyUDP(downstream *gonet.UDPConn, target netip.AddrPort) {
	defer downstream.Close()

	// A physical-bypass packet conn, unconnected so we can send to `target`
	// explicitly. The caller's ListenPacket should bind to the physical iface.
	upstream, err := s.cfg.PhysicalDialer.ListenPacket(s.ctx, "udp", ":0")
	if err != nil {
		return
	}
	defer upstream.Close()

	targetUDP := &net.UDPAddr{IP: target.Addr().AsSlice(), Port: int(target.Port())}

	// downstream → upstream
	go func() {
		buf := make([]byte, 64*1024)
		for {
			_ = downstream.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := downstream.Read(buf)
			if err != nil {
				upstream.Close()
				return
			}
			if _, err := upstream.WriteTo(buf[:n], targetUDP); err != nil {
				return
			}
		}
	}()
	// upstream → downstream
	buf := make([]byte, 64*1024)
	for {
		_ = upstream.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, _, err := upstream.ReadFrom(buf)
		if err != nil {
			return
		}
		if _, err := downstream.Write(buf[:n]); err != nil {
			return
		}
	}
}

// splice is the usual full-duplex copy with one done signal.
func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	<-done
}

// addrFromTcpip converts a gvisor tcpip.Address back to a netip.Addr.
func addrFromTcpip(a tcpip.Address) netip.Addr {
	if a.Len() == 16 {
		return netip.AddrFrom16(a.As16())
	}
	if a.Len() == 4 {
		return netip.AddrFrom4(a.As4())
	}
	return netip.Addr{}
}

