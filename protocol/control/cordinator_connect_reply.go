package control

import (
	"encoding/binary"
	"fmt"
)

// CordinatorConnectReply is sent by the cordinator in response to a
// successful CordinatorConnect. Peers is the cordinator's current
// view of every operator already attached (UUID + underlay endpoint),
// so the new operator can preload its PeerTable instead of waiting
// for separate PeerJoin events to arrive.
type CordinatorConnectReply struct {
	Peers []PeerJoin
}

func (CordinatorConnectReply) opMarker() {}
func (CordinatorConnectReply) Kind() Kind { return KindCordinatorConnectReply }

// Wire layout: PeerCount(2) + repeat[ UUID(16) + AddrLen(1) + Addr + Port(2) ].
func (r *CordinatorConnectReply) Encode() []byte {
	// Pre-size by summing per-peer encoded lengths.
	total := 2
	for _, p := range r.Peers {
		total += 16 + 1 + p.Endpoint.Addr().BitLen()/8 + 2
	}
	out := make([]byte, 0, total)
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(r.Peers)))
	out = append(out, hdr[:]...)
	for i := range r.Peers {
		out = append(out, r.Peers[i].Encode()...)
	}
	return out
}

func (r *CordinatorConnectReply) Decode(b []byte) error {
	if len(b) < 2 {
		return fmt.Errorf("cordinator-connect-reply: short %d", len(b))
	}
	n := int(binary.BigEndian.Uint16(b[0:2]))
	off := 2
	r.Peers = make([]PeerJoin, 0, n)
	for i := 0; i < n; i++ {
		if len(b) < off+16+1 {
			return fmt.Errorf("cordinator-connect-reply: peer %d truncated", i)
		}
		addrLen := int(b[off+16])
		entryLen := 16 + 1 + addrLen + 2
		if len(b) < off+entryLen {
			return fmt.Errorf("cordinator-connect-reply: peer %d truncated", i)
		}
		var pj PeerJoin
		if err := pj.Decode(b[off : off+entryLen]); err != nil {
			return fmt.Errorf("cordinator-connect-reply: peer %d: %w", i, err)
		}
		r.Peers = append(r.Peers, pj)
		off += entryLen
	}
	return nil
}

