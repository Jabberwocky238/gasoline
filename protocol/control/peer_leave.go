package control

import "fmt"

// PeerLeave announces that an operator UUID has gone away. Recipients
// remove the peer from their PeerTable; routes pinned to this UUID
// become unreachable until a fresh PeerJoin lands.
type PeerLeave struct {
	UUID [16]byte
}

func (PeerLeave) opMarker() {}
func (PeerLeave) Kind() Kind { return KindPeerLeave }

// Wire layout: UUID(16).
func (p *PeerLeave) Encode() []byte {
	out := make([]byte, 16)
	copy(out, p.UUID[:])
	return out
}

func (p *PeerLeave) Decode(b []byte) error {
	if len(b) < 16 {
		return fmt.Errorf("peer-leave: short %d", len(b))
	}
	copy(p.UUID[:], b[:16])
	return nil
}
