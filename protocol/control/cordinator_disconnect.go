package control

import (
	"encoding/binary"
	"fmt"
)

// CordinatorDisconnect tells the operator to tear down the
// CordinatorController targeting Endpoint, if any.
type CordinatorDisconnect struct {
	Endpoint string
}

func (CordinatorDisconnect) opMarker() {}
func (CordinatorDisconnect) Kind() Kind { return KindCordinatorDisconnect }

// Wire layout: EndpointLen(2) + Endpoint(N).
func (c *CordinatorDisconnect) Encode() []byte {
	out := make([]byte, 2+len(c.Endpoint))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(c.Endpoint)))
	copy(out[2:], c.Endpoint)
	return out
}

func (c *CordinatorDisconnect) Decode(b []byte) error {
	if len(b) < 2 {
		return fmt.Errorf("cordinator-disconnect: short %d", len(b))
	}
	n := int(binary.BigEndian.Uint16(b[0:2]))
	if len(b) < 2+n {
		return fmt.Errorf("cordinator-disconnect: short %d (need %d)", len(b), 2+n)
	}
	c.Endpoint = string(b[2 : 2+n])
	return nil
}
