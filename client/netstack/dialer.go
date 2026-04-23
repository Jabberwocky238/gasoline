package netstack

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"

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
	return conn, nil
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
