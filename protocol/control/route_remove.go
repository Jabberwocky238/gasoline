package control

import (
	"encoding/binary"
	"fmt"

	"github.com/jabberwocky238/gasoline/protocol"
)

// RouteRemove drops the (vni, cid) binding from the routing table on
// the recipient.
type RouteRemove struct {
	VNI protocol.VNI_Ty
	CID protocol.CID_Ty
}

func (RouteRemove) opMarker() {}
func (RouteRemove) Kind() Kind { return KindRouteRemove }

// Wire layout: VNI(4) + CID(8).
func (r *RouteRemove) Encode() []byte {
	out := make([]byte, 4+8)
	binary.BigEndian.PutUint32(out[0:4], uint32(r.VNI))
	copy(out[4:12], r.CID[:])
	return out
}

func (r *RouteRemove) Decode(b []byte) error {
	if len(b) < 12 {
		return fmt.Errorf("route-remove: short %d", len(b))
	}
	r.VNI = protocol.VNI_Ty(binary.BigEndian.Uint32(b[0:4]))
	copy(r.CID[:], b[4:12])
	return nil
}
