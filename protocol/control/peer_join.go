package control

import "net/netip"

// PeerJoin announces that an operator UUID is reachable at the given
// underlay endpoint. Recipients add the peer to their PeerTable so
// outbound RouteTargetOperator forwards land at Endpoint.
type PeerJoin struct {
	UUID     [16]byte       `json:"uuid"`
	Endpoint netip.AddrPort `json:"endpoint"`
}

func (PeerJoin) opMarker() {}
func (PeerJoin) Kind() Kind { return KindPeerJoin }
