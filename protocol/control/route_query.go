package control

import (
	"encoding/binary"
	"fmt"

	"github.com/jabberwocky238/gasoline/protocol"
)

// RouteQuery asks the recipient for the prefix bound to (vni, cid).
// Only meaningful in request/response surfaces (gasoctl IPC); the
// answer is delivered as a Reply.
type RouteQuery struct {
	VNI protocol.VNI_Ty
	CID protocol.CID_Ty
}

func (RouteQuery) opMarker() {}
func (RouteQuery) Kind() Kind { return KindRouteQuery }

// Wire layout: VNI(4) + CID(8).
func (r *RouteQuery) Encode() []byte {
	out := make([]byte, 4+8)
	binary.BigEndian.PutUint32(out[0:4], uint32(r.VNI))
	copy(out[4:12], r.CID[:])
	return out
}

func (r *RouteQuery) Decode(b []byte) error {
	if len(b) < 12 {
		return fmt.Errorf("route-query: short %d", len(b))
	}
	r.VNI = protocol.VNI_Ty(binary.BigEndian.Uint32(b[0:4]))
	copy(r.CID[:], b[4:12])
	return nil
}
