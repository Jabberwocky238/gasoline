package control

// Reply is the answer to a request-shaped Op (e.g. RouteQuery).
//
//	OK == true  : Payload carries the success body (may be empty)
//	OK == false : Payload carries a human-readable error message
type Reply struct {
	OK      bool   `json:"ok"`
	Payload string `json:"payload,omitempty"`
}

func (Reply) opMarker() {}
func (Reply) Kind() Kind { return KindReply }
