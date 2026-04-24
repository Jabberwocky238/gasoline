package netstack

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
)

// dialSocks5 opens a TCP connection *through the gvisor stack* to the SOCKS5
// peer, routed via NIC-OVERLAY, then speaks the SOCKS5 no-auth CONNECT
// handshake. The returned net.Conn is a gonet.TCPConn whose bytes show up on
// OnOverlayWrite — never on the OS TUN. That's the "avoid double TUN" trick:
// the SOCKS5 upstream's SYN/ACKs are minted in userspace and shipped straight
// out the overlay transport.
func (s *Stack) dialSocks5(ctx context.Context, target netip.AddrPort) (net.Conn, error) {
	peer := s.cfg.Socks5Peer
	if !peer.IsValid() {
		return nil, errors.New("netstack: SOCKS5 not configured")
	}
	// Self-IP family must match peer IP family — the local bind is required
	// so gvisor picks the right protocol address on NIC-OVERLAY.
	if s.cfg.LocalIP.Is4() != peer.Addr().Is4() {
		return nil, fmt.Errorf("netstack: LocalIP/Socks5Peer family mismatch")
	}

	peerTcpip, proto := protoAddress(peer.Addr())
	localTcpip, _ := protoAddress(s.cfg.LocalIP)

	local := tcpip.FullAddress{NIC: nicOverlay, Addr: localTcpip, Port: 0}
	remote := tcpip.FullAddress{NIC: nicOverlay, Addr: peerTcpip, Port: peer.Port()}

	conn, err := gonet.DialTCPWithBind(ctx, s.ipStack, local, remote, proto)
	if err != nil {
		return nil, fmt.Errorf("dial socks5 peer: %w", err)
	}
	if err := socks5ClientHandshake(conn, target); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 handshake: %w", err)
	}
	// Register the local port so MaybeHandleOverlayInbound can route return
	// traffic back into the stack instead of letting it hit the OS TUN.
	localPort := uint16(conn.LocalAddr().(*net.TCPAddr).Port)
	s.registerFlow(protoTCP, localPort)
	return &trackedTCPConn{Conn: conn, stack: s, port: localPort}, nil
}

// trackedTCPConn wraps a gonet.TCPConn returned from dialSocks5 so that the
// stack's flow-table registration is cleaned up whenever the caller closes
// the connection. Wrapping keeps the outer net.Conn contract identical and
// adds a single sync.Once around the unregister call.
type trackedTCPConn struct {
	net.Conn
	stack *Stack
	port  uint16
	once  sync.Once
}

func (c *trackedTCPConn) Close() error {
	c.once.Do(func() { c.stack.unregisterFlow(protoTCP, c.port) })
	return c.Conn.Close()
}

// socks5ClientHandshake runs the no-auth SOCKS5 greeting and a single CONNECT
// request. On success the connection is ready for plain user bytes.
func socks5ClientHandshake(c net.Conn, target netip.AddrPort) error {
	// Greeting: VER=5, NMETHODS=1, METHOD=NoAuth(0x00)
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	// Server selects method.
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		return err
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		return fmt.Errorf("unexpected method select: %v", reply)
	}

	// CONNECT request: VER=5, CMD=CONNECT(1), RSV=0, ATYP, ADDR, PORT.
	var req []byte
	addr := target.Addr()
	if addr.Is4() {
		req = append(req, 0x05, 0x01, 0x00, 0x01)
		b := addr.As4()
		req = append(req, b[:]...)
	} else {
		req = append(req, 0x05, 0x01, 0x00, 0x04)
		b := addr.As16()
		req = append(req, b[:]...)
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], target.Port())
	req = append(req, port[:]...)
	if _, err := c.Write(req); err != nil {
		return err
	}

	// Response: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT.
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return err
	}
	if head[0] != 0x05 {
		return fmt.Errorf("bad version in reply: %d", head[0])
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks5 CONNECT failed, rep=%d", head[1])
	}
	// Skip the bind address + port without caring about their value.
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return err
		}
		skip = int(l[0])
	default:
		return fmt.Errorf("unknown ATYP: %d", head[3])
	}
	if _, err := io.ReadFull(c, make([]byte, skip+2)); err != nil {
		return err
	}
	return nil
}

// ---- SOCKS5 UDP ASSOCIATE -------------------------------------------------

// dialSocks5UDP opens a SOCKS5 UDP relay for one logical UDP flow. It:
//  1. Dials a TCP control connection to the SOCKS5 peer over NIC-OVERLAY.
//  2. Sends a UDP ASSOCIATE request, parses the BND.ADDR/BND.PORT reply.
//  3. Dials a gonet.UDPConn over NIC-OVERLAY to BND.ADDR:BND.PORT.
//  4. Returns a net.PacketConn whose WriteTo/ReadFrom wrap the SOCKS5 UDP
//     header around every datagram.
//
// The returned PacketConn also watches the TCP control side: if the control
// connection dies (peer restart, network drop), Close is invoked on the
// whole wrapper so proxyUDP's goroutines unblock.
//
// The target is fixed at dial time because the gvisor UDP forwarder calls
// handleUDP once per 5-tuple — there is no need for per-packet retargeting
// in this caller. Callers of WriteTo may pass any addr; it is ignored.
func (s *Stack) dialSocks5UDP(ctx context.Context, target netip.AddrPort) (net.PacketConn, error) {
	peer := s.cfg.Socks5Peer
	if !peer.IsValid() {
		return nil, errors.New("netstack: SOCKS5 not configured")
	}
	if s.cfg.LocalIP.Is4() != peer.Addr().Is4() {
		return nil, fmt.Errorf("netstack: LocalIP/Socks5Peer family mismatch")
	}

	peerTcpip, proto := protoAddress(peer.Addr())
	localTcpip, _ := protoAddress(s.cfg.LocalIP)

	local := tcpip.FullAddress{NIC: nicOverlay, Addr: localTcpip, Port: 0}
	remote := tcpip.FullAddress{NIC: nicOverlay, Addr: peerTcpip, Port: peer.Port()}

	ctrl, err := gonet.DialTCPWithBind(ctx, s.ipStack, local, remote, proto)
	if err != nil {
		return nil, fmt.Errorf("dial socks5 ctrl: %w", err)
	}
	ctrlPort := uint16(ctrl.LocalAddr().(*net.TCPAddr).Port)
	s.registerFlow(protoTCP, ctrlPort)

	bnd, err := socks5UDPAssociate(ctrl)
	if err != nil {
		s.unregisterFlow(protoTCP, ctrlPort)
		ctrl.Close()
		return nil, fmt.Errorf("socks5 UDP associate: %w", err)
	}
	if bnd.Addr().Is4() != s.cfg.LocalIP.Is4() {
		s.unregisterFlow(protoTCP, ctrlPort)
		ctrl.Close()
		return nil, fmt.Errorf("socks5 BND family mismatch: got %s", bnd.Addr())
	}

	bndTcpip, _ := protoAddress(bnd.Addr())
	udpLocal := tcpip.FullAddress{NIC: nicOverlay, Addr: localTcpip, Port: 0}
	udpRemote := tcpip.FullAddress{NIC: nicOverlay, Addr: bndTcpip, Port: bnd.Port()}

	udpConn, err := gonet.DialUDP(s.ipStack, &udpLocal, &udpRemote, proto)
	if err != nil {
		s.unregisterFlow(protoTCP, ctrlPort)
		ctrl.Close()
		return nil, fmt.Errorf("dial socks5 udp relay: %w", err)
	}
	udpPort := uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)
	s.registerFlow(protoUDP, udpPort)

	return newSocks5UDPPacketConn(ctrl, udpConn, target, s, ctrlPort, udpPort), nil
}

// socks5UDPAssociate runs the SOCKS5 no-auth greeting then sends a UDP
// ASSOCIATE (CMD=3) with a wildcard source (0.0.0.0:0). Returns the BND
// address the server listens on — that's where we send wrapped datagrams.
func socks5UDPAssociate(c net.Conn) (netip.AddrPort, error) {
	// Greeting: VER=5 NMETHODS=1 METHOD=0 (no auth).
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return netip.AddrPort{}, err
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(c, sel); err != nil {
		return netip.AddrPort{}, err
	}
	if sel[0] != 0x05 || sel[1] != 0x00 {
		return netip.AddrPort{}, fmt.Errorf("method select: %v", sel)
	}
	// UDP ASSOCIATE: VER=5 CMD=3 RSV=0 ATYP=1 0.0.0.0 PORT=0.
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := c.Write(req); err != nil {
		return netip.AddrPort{}, err
	}
	// Reply head: VER REP RSV ATYP.
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return netip.AddrPort{}, err
	}
	if head[0] != 0x05 {
		return netip.AddrPort{}, fmt.Errorf("bad version in reply: %d", head[0])
	}
	if head[1] != 0x00 {
		return netip.AddrPort{}, fmt.Errorf("UDP ASSOCIATE failed, rep=%d", head[1])
	}
	var bndAddr netip.Addr
	switch head[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return netip.AddrPort{}, err
		}
		bndAddr = netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]})
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return netip.AddrPort{}, err
		}
		var a [16]byte
		copy(a[:], b)
		bndAddr = netip.AddrFrom16(a)
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return netip.AddrPort{}, err
		}
		// Domain BND is legal per RFC but nonsensical here: we need an IP to
		// dial on NIC-OVERLAY. Treat as a server misconfiguration.
		_, _ = io.ReadFull(c, make([]byte, int(l[0])))
		return netip.AddrPort{}, fmt.Errorf("BND ATYP=domain not supported")
	default:
		return netip.AddrPort{}, fmt.Errorf("unknown BND ATYP: %d", head[3])
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(c, portBuf); err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(bndAddr, binary.BigEndian.Uint16(portBuf)), nil
}

// socks5UDPPacketConn is the net.PacketConn returned by dialSocks5UDP.
// Internally it bundles the TCP control conn and the overlay-side UDP conn
// and speaks the SOCKS5 UDP header format on every WriteTo / ReadFrom.
//
// rdBuf is deliberately NOT drawn from proxyBufPool: it is live across
// concurrent Close + ReadFrom windows (Close triggered by proxyUDP's main
// goroutine while the reader goroutine may still be inside c.udp.Read).
// Returning it to a shared pool before the reader exits risks handing a
// buffer to another flow while gvisor writes into it. The 64 KB per-conn
// cost is acceptable.
type socks5UDPPacketConn struct {
	ctrl   net.Conn
	udp    net.Conn
	target netip.AddrPort

	rdBuf     []byte // reused across ReadFrom calls; caller is single-reader
	closeOnce sync.Once

	// stack+ports carry the flow-table registration we must unregister on
	// Close. Zero stack means "don't touch the flow table" (used by unit
	// tests that construct this type directly without going through a Stack).
	stack    *Stack
	ctrlPort uint16
	udpPort  uint16
}

func newSocks5UDPPacketConn(ctrl, udp net.Conn, target netip.AddrPort, s *Stack, ctrlPort, udpPort uint16) *socks5UDPPacketConn {
	c := &socks5UDPPacketConn{
		ctrl:     ctrl,
		udp:      udp,
		target:   target,
		rdBuf:    make([]byte, 64*1024+64),
		stack:    s,
		ctrlPort: ctrlPort,
		udpPort:  udpPort,
	}
	// Watchdog: if the control connection dies (peer restart, RST, etc.),
	// tear down the whole wrapper so proxyUDP's Read loop unblocks.
	go func() {
		_, _ = io.Copy(io.Discard, ctrl)
		c.Close()
	}()
	return c
}

func (c *socks5UDPPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	hdr := buildSocks5UDPHeader(c.target)
	buf := make([]byte, len(hdr)+len(p))
	copy(buf, hdr)
	copy(buf[len(hdr):], p)
	if _, err := c.udp.Write(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *socks5UDPPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.udp.Read(c.rdBuf)
	if err != nil {
		return 0, nil, err
	}
	hdrLen, perr := parseSocks5UDPHeader(c.rdBuf[:n])
	if perr != nil {
		// Treat as a dropped datagram rather than an error — peer may send
		// a malformed frame occasionally; returning err would kill the conn.
		return 0, nil, perr
	}
	payload := c.rdBuf[hdrLen:n]
	copied := copy(p, payload)
	return copied, net.UDPAddrFromAddrPort(c.target), nil
}

func (c *socks5UDPPacketConn) Close() error {
	c.closeOnce.Do(func() {
		_ = c.udp.Close()
		_ = c.ctrl.Close()
		if c.stack != nil {
			c.stack.unregisterFlow(protoTCP, c.ctrlPort)
			c.stack.unregisterFlow(protoUDP, c.udpPort)
		}
	})
	return nil
}

func (c *socks5UDPPacketConn) LocalAddr() net.Addr { return c.udp.LocalAddr() }

func (c *socks5UDPPacketConn) SetDeadline(t time.Time) error {
	if err := c.udp.SetDeadline(t); err != nil {
		return err
	}
	return nil
}

func (c *socks5UDPPacketConn) SetReadDeadline(t time.Time) error {
	return c.udp.SetReadDeadline(t)
}

func (c *socks5UDPPacketConn) SetWriteDeadline(t time.Time) error {
	return c.udp.SetWriteDeadline(t)
}

// buildSocks5UDPHeader returns the wire prefix for one client-to-server
// SOCKS5 UDP datagram: [RSV=0 RSV=0 FRAG=0 ATYP ADDR PORT].
func buildSocks5UDPHeader(target netip.AddrPort) []byte {
	addr := target.Addr()
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], target.Port())
	if addr.Is4() {
		b := addr.As4()
		hdr := make([]byte, 0, 10)
		hdr = append(hdr, 0x00, 0x00, 0x00, 0x01)
		hdr = append(hdr, b[:]...)
		hdr = append(hdr, port[:]...)
		return hdr
	}
	b := addr.As16()
	hdr := make([]byte, 0, 22)
	hdr = append(hdr, 0x00, 0x00, 0x00, 0x04)
	hdr = append(hdr, b[:]...)
	hdr = append(hdr, port[:]...)
	return hdr
}

// parseSocks5UDPHeader returns the header length so the caller can slice
// the payload. Validates RSV, FRAG, and ATYP. Rejects FRAG != 0 because we
// don't implement reassembly; fragmented datagrams are dropped upstream.
func parseSocks5UDPHeader(pkt []byte) (int, error) {
	if len(pkt) < 4 {
		return 0, errors.New("socks5 udp: short header")
	}
	if pkt[0] != 0 || pkt[1] != 0 {
		return 0, errors.New("socks5 udp: RSV != 0")
	}
	if pkt[2] != 0 {
		return 0, errors.New("socks5 udp: FRAG != 0 not supported")
	}
	off := 4
	switch pkt[3] {
	case 0x01:
		off += 4
	case 0x04:
		off += 16
	case 0x03:
		if len(pkt) < off+1 {
			return 0, errors.New("socks5 udp: truncated domain atyp")
		}
		off += 1 + int(pkt[off])
	default:
		return 0, fmt.Errorf("socks5 udp: unknown ATYP %d", pkt[3])
	}
	off += 2 // port
	if len(pkt) < off {
		return 0, errors.New("socks5 udp: truncated header")
	}
	return off, nil
}
