package control

import (
	"encoding/binary"
	"fmt"
)

// CordinatorConnect tells the operator to dial a remote cordinator at
// Endpoint and start a CordinatorController against it.
type CordinatorConnect struct {
	Endpoint string
}

func (CordinatorConnect) opMarker() {}
func (CordinatorConnect) Kind() Kind { return KindCordinatorConnect }

// Wire layout: EndpointLen(2) + Endpoint(N).
func (c *CordinatorConnect) Encode() []byte {
	out := make([]byte, 2+len(c.Endpoint))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(c.Endpoint)))
	copy(out[2:], c.Endpoint)
	return out
}

func (c *CordinatorConnect) Decode(b []byte) error {
	if len(b) < 2 {
		return fmt.Errorf("cordinator-connect: short %d", len(b))
	}
	n := int(binary.BigEndian.Uint16(b[0:2]))
	if len(b) < 2+n {
		return fmt.Errorf("cordinator-connect: short %d (need %d)", len(b), 2+n)
	}
	c.Endpoint = string(b[2 : 2+n])
	return nil
}
