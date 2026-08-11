package control

import "github.com/jabberwocky238/gasoline/protocol"

// RouteQuery asks the recipient for the prefix bound to (vni, cid).
// Only meaningful in request/response surfaces (gasoctl IPC); the
// answer is delivered as a Reply.
type RouteQuery struct {
	VNI protocol.VNI_Ty `json:"vni"`
	SessionID protocol.SessionID_Ty `json:"session_id"`
}

func (RouteQuery) opMarker() {}
func (RouteQuery) Kind() Kind { return KindRouteQuery }
