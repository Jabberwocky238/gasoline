package control

import (
	"encoding/binary"
	"fmt"
)

// Reply is the answer to a request-shaped Op (e.g. RouteQuery).
//
//	OK == true  : Payload carries the success body (may be empty)
//	OK == false : Payload carries a human-readable error message
type Reply struct {
	OK      bool
	Payload string
}

func (Reply) opMarker() {}
func (Reply) Kind() Kind { return KindReply }

// Wire layout: OK(1) + PayloadLen(2) + Payload(N).
func (r *Reply) Encode() []byte {
	out := make([]byte, 1+2+len(r.Payload))
	if r.OK {
		out[0] = 1
	}
	binary.BigEndian.PutUint16(out[1:3], uint16(len(r.Payload)))
	copy(out[3:], r.Payload)
	return out
}

func (r *Reply) Decode(b []byte) error {
	if len(b) < 3 {
		return fmt.Errorf("reply: short %d", len(b))
	}
	r.OK = b[0] != 0
	n := int(binary.BigEndian.Uint16(b[1:3]))
	if len(b) < 3+n {
		return fmt.Errorf("reply: short %d (need %d)", len(b), 3+n)
	}
	r.Payload = string(b[3 : 3+n])
	return nil
}
