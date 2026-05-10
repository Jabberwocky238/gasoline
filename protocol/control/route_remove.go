package control

import "github.com/jabberwocky238/gasoline/protocol"

// RouteRemove drops the (vni, cid) binding from the routing table on
// the recipient.
type RouteRemove struct {
	VNI protocol.VNI_Ty `json:"vni"`
	CID protocol.CID_Ty `json:"cid"`
}

func (RouteRemove) opMarker() {}
func (RouteRemove) Kind() Kind { return KindRouteRemove }
