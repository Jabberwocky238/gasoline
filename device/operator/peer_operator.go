package operator

import (
	"net"
	"net/netip"
)

type PeerOperator struct {
	UUID    [16]byte
	UDPAddr netip.AddrPort
	conn    *net.UDPConn
}

func NewPeerOperator(uuid [16]byte, udpAddr netip.AddrPort) *PeerOperator {
	return &PeerOperator{UUID: uuid, UDPAddr: udpAddr}
}
