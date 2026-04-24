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
	target := netip.AddrPortFrom(dst, dstPort)

	decision := s.classifyDial(dst)
	switch decision {
	case dialPhysical, dialSocks5:
	default:
		return true // drop
	}

	var wq waiter.Queue
	ep, terr := req.CreateEndpoint(&wq)
	if terr != nil {
		return true
	}
	downstream := gonet.NewUDPConn(&wq, ep)

	go s.proxyUDP(downstream, target, decision)
	return true
}

// proxyUDP shuttles datagrams between an accepted gonet.UDPConn and an
// upstream net.PacketConn for as long as either side sees traffic within
// UDPIdleTimeout. The upstream shape depends on the dial decision:
//
//   - dialPhysical ⇒ PhysicalDialer.ListenPacket, WriteTo(target), ReadFrom.
//   - dialSocks5   ⇒ dialSocks5UDP, whose WriteTo wraps SOCKS5 UDP headers
//     and ReadFrom strips them. Caller's address arg to WriteTo is ignored
//     because the target is fixed at dial time.
func (s *Stack) proxyUDP(downstream *gonet.UDPConn, target netip.AddrPort, decision dialDecision) {
	defer downstream.Close()

	idle := s.cfg.udpIdleTimeout()
	writeTO := s.cfg.udpWriteTimeout()

	var (
		upstream net.PacketConn
		err      error
	)
	switch decision {
	case dialPhysical:
		upstream, err = s.cfg.PhysicalDialer.ListenPacket(s.ctx, "udp", ":0")
	case dialSocks5:
		upstream, err = s.dialSocks5UDP(s.ctx, target)
	}
	if err != nil {
		return
	}
	defer upstream.Close()

	targetUDP := &net.UDPAddr{IP: target.Addr().AsSlice(), Port: int(target.Port())}

	// Shared "first side to error out wins" channel: whichever direction
	// hits an error (including idle timeout) triggers both closes via
	// defer. cap=2 so the second sender never blocks on the unreceiver.
	done := make(chan struct{}, 2)

	// downstream (app) → upstream
	go func() {
		defer func() { done <- struct{}{} }()
		bufPtr := getProxyBuf()
		defer putProxyBuf(bufPtr)
		buf := *bufPtr
		for {
			_ = downstream.SetReadDeadline(time.Now().Add(idle))
			n, err := downstream.Read(buf)
			if err != nil {
				return
			}
			_ = upstream.SetWriteDeadline(time.Now().Add(writeTO))
			if _, err := upstream.WriteTo(buf[:n], targetUDP); err != nil {
				return
			}
		}
	}()

	// upstream → downstream (app)
	go func() {
		defer func() { done <- struct{}{} }()
		bufPtr := getProxyBuf()
		defer putProxyBuf(bufPtr)
		buf := *bufPtr
		for {
			_ = upstream.SetReadDeadline(time.Now().Add(idle))
			n, _, err := upstream.ReadFrom(buf)
			if err != nil {
				return
			}
			_ = downstream.SetWriteDeadline(time.Now().Add(writeTO))
			if _, err := downstream.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	<-done
}

// splice is the usual full-duplex copy with one done signal. Uses pooled
// buffers via io.CopyBuffer so we don't allocate a fresh 32K per direction
// per flow; the pool buffer is only actually used when neither end
// implements WriterTo/ReaderFrom (which is the common case for gvisor's
// gonet.TCPConn on at least one side).
func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		bufPtr := getProxyBuf()
		defer putProxyBuf(bufPtr)
		_, _ = io.CopyBuffer(a, b, *bufPtr)
		done <- struct{}{}
	}()
	go func() {
		bufPtr := getProxyBuf()
		defer putProxyBuf(bufPtr)
		_, _ = io.CopyBuffer(b, a, *bufPtr)
		done <- struct{}{}
	}()
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

