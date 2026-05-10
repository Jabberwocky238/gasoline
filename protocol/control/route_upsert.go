package control

import (
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
	VNI       protocol.VNI_Ty `json:"vni"`
	CID       protocol.CID_Ty `json:"cid"`
	Prefix    netip.Prefix    `json:"prefix"`
	OwnerUUID [16]byte        `json:"ownerUUID,omitempty"`
}

func (RouteUpsert) opMarker() {}
func (RouteUpsert) Kind() Kind { return KindRouteUpsert }
