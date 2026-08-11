package operator

import (
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
)

// PeerOperator is a remote operator on the same VNI mesh. Outbound
// frames are sent UDP-to-UDP directly to its UDPAddr through a shared
// socket owned by the local Operator (set via SetSendSocket).
type PeerOperator struct {
	UUID    [16]byte
	UDPAddr netip.AddrPort

	// send is the local operator's UDP socket; one socket fan-outs to
	// every peer. nil before Operator.Start binds it.
	send atomic.Pointer[net.UDPConn]
}

func NewPeerOperator(uuid [16]byte, udpAddr netip.AddrPort) *PeerOperator {
	return &PeerOperator{UUID: uuid, UDPAddr: udpAddr}
}

// SetSendSocket installs the shared local UDP socket used to write to
// this peer.
func (p *PeerOperator) SetSendSocket(c *net.UDPConn) { p.send.Store(c) }

// WritePacket sends raw bytes to the peer's UDPAddr. Caller is
// expected to pass an already-encoded MessageTransport byte slice.
func (p *PeerOperator) WritePacket(b []byte) error {
	c := p.send.Load()
	if c == nil {
		return fmt.Errorf("peer %x: no send socket bound", p.UUID)
	}
	udpAddr := net.UDPAddrFromAddrPort(p.UDPAddr)
	_, err := c.WriteToUDP(b, udpAddr)
	return err
}
