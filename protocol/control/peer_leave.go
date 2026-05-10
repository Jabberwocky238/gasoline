package control

// PeerLeave announces that an operator UUID has gone away. Recipients
// remove the peer from their PeerTable; routes pinned to this UUID
// become unreachable until a fresh PeerJoin lands.
type PeerLeave struct {
	UUID [16]byte `json:"uuid"`
}

func (PeerLeave) opMarker() {}
func (PeerLeave) Kind() Kind { return KindPeerLeave }
