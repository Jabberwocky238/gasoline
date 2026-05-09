package operator

import (
	"net/netip"
)

// PeerOperator is a remote operator: UUID + data-plane UDP endpoint. Populated from
// the coordinator's PeerSnapshot/Joined/Left events. No connection state — all
// operator-to-operator traffic flows over the shared VXLAN UDP socket.
type PeerOperator struct {
	UUID    [16]byte
	UDPAddr netip.AddrPort
}

func NewPeer(uuid [16]byte, udpAddr netip.AddrPort) *PeerOperator {
	return &PeerOperator{UUID: uuid, UDPAddr: udpAddr}
}
