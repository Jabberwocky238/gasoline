package control

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/jabberwocky238/gasoline/protocol"
)

// RouteUpsert installs or replaces a (vni, cid) -> prefix binding.
//
// OwnerUUID names the operator that terminates the client side of
// this route. Zero value means "the receiving operator owns it
// locally" (i.e. the client is connected to this operator); a non-zero
// UUID means "reach this prefix via that peer operator".
type RouteUpsert struct {
	VNI       protocol.VNI_Ty
	CID       protocol.CID_Ty
	Prefix    netip.Prefix
	OwnerUUID [16]byte
}

func (RouteUpsert) opMarker() {}
func (RouteUpsert) Kind() Kind { return KindRouteUpsert }

// Wire layout: VNI(4) + CID(8) + AddrLen(1) + Addr(0/4/16) + CIDRBits(1) + UUID(16).
func (r *RouteUpsert) Encode() []byte {
	addr := r.Prefix.Addr().AsSlice()
	out := make([]byte, 4+8+1+len(addr)+1+16)
	off := 0
	binary.BigEndian.PutUint32(out[off:off+4], uint32(r.VNI))
	off += 4
	copy(out[off:off+8], r.CID[:])
	off += 8
	out[off] = byte(len(addr))
	off++
	copy(out[off:off+len(addr)], addr)
	off += len(addr)
	out[off] = byte(r.Prefix.Bits())
	off++
	copy(out[off:off+16], r.OwnerUUID[:])
	return out
}

func (r *RouteUpsert) Decode(b []byte) error {
	if len(b) < 4+8+1 {
		return fmt.Errorf("route-upsert: short %d", len(b))
	}
	off := 0
	r.VNI = protocol.VNI_Ty(binary.BigEndian.Uint32(b[off : off+4]))
	off += 4
	copy(r.CID[:], b[off:off+8])
	off += 8
	addrLen := int(b[off])
	off++
	if len(b) < off+addrLen+1+16 {
		return fmt.Errorf("route-upsert: short %d (need %d)", len(b), off+addrLen+1+16)
	}
	var addr netip.Addr
	if addrLen > 0 {
		a, ok := netip.AddrFromSlice(b[off : off+addrLen])
		if !ok {
			return fmt.Errorf("route-upsert: bad addr len %d", addrLen)
		}
		addr = a
	}
	off += addrLen
	bits := int(b[off])
	off++
	if addr.IsValid() {
		r.Prefix = netip.PrefixFrom(addr, bits)
	} else {
		r.Prefix = netip.Prefix{}
	}
	copy(r.OwnerUUID[:], b[off:off+16])
	return nil
}
