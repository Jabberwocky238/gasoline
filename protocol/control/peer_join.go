package control

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// PeerJoin announces that an operator UUID is reachable at the given
// underlay endpoint. Recipients add the peer to their PeerTable so
// outbound RouteTargetOperator forwards land at Endpoint.
type PeerJoin struct {
	UUID     [16]byte
	Endpoint netip.AddrPort
}

func (PeerJoin) opMarker() {}
func (PeerJoin) Kind() Kind { return KindPeerJoin }

// Wire layout: UUID(16) + AddrLen(1) + Addr(0/4/16) + Port(2).
func (p *PeerJoin) Encode() []byte {
	addr := p.Endpoint.Addr().AsSlice()
	out := make([]byte, 16+1+len(addr)+2)
	off := 0
	copy(out[off:off+16], p.UUID[:])
	off += 16
	out[off] = byte(len(addr))
	off++
	copy(out[off:off+len(addr)], addr)
	off += len(addr)
	binary.BigEndian.PutUint16(out[off:off+2], p.Endpoint.Port())
	return out
}

func (p *PeerJoin) Decode(b []byte) error {
	if len(b) < 16+1 {
		return fmt.Errorf("peer-join: short %d", len(b))
	}
	off := 0
	copy(p.UUID[:], b[off:off+16])
	off += 16
	addrLen := int(b[off])
	off++
	if len(b) < off+addrLen+2 {
		return fmt.Errorf("peer-join: short %d (need %d)", len(b), off+addrLen+2)
	}
	var addr netip.Addr
	if addrLen > 0 {
		a, ok := netip.AddrFromSlice(b[off : off+addrLen])
		if !ok {
			return fmt.Errorf("peer-join: bad addr len %d", addrLen)
		}
		addr = a
	}
	off += addrLen
	port := binary.BigEndian.Uint16(b[off : off+2])
	if addr.IsValid() {
		p.Endpoint = netip.AddrPortFrom(addr, port)
	} else {
		p.Endpoint = netip.AddrPort{}
	}
	return nil
}
