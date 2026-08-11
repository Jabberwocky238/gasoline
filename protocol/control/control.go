// Package control defines the vocabulary used by gasoctl (operator
// IPC over Unix socket). One op per file.
//
// This is a CONTROL plane — bandwidth is irrelevant. Encoding is
// JSON via MarshalJSON / UnmarshalJSON in json.go. There is
// intentionally no per-struct binary Encode/Decode.
package control

import (
	"encoding/json"
	"fmt"
)

// Op is the union over all operation kinds defined in this package.
// Concrete types live in their own files; the only behavior the
// dispatcher needs is the Kind discriminator.
type Op interface {
	opMarker()
	Kind() Kind
}

// Kind is a stable per-op tag. Used in the JSON envelope so receivers
// can pick a concrete struct before unmarshalling the body.
type Kind uint8

const (
	KindUnknown     Kind = 0x00
	KindRouteUpsert Kind = 0x01
	KindRouteRemove Kind = 0x02
	KindRouteQuery  Kind = 0x03
	KindPeerJoin    Kind = 0x10
	KindPeerLeave   Kind = 0x11
	KindReply       Kind = 0xF0
)

// New returns a zero-valued Op for the given kind, ready to be
// populated by json.Unmarshal. Returns nil for unknown kinds.
func New(k Kind) Op {
	switch k {
	case KindRouteUpsert:
		return &RouteUpsert{}
	case KindRouteRemove:
		return &RouteRemove{}
	case KindRouteQuery:
		return &RouteQuery{}
	case KindPeerJoin:
		return &PeerJoin{}
	case KindPeerLeave:
		return &PeerLeave{}
	case KindReply:
		return &Reply{}
	}
	return nil
}

// JSON envelope wraps any Op so the receiver can dispatch by Kind
// before unmarshalling into the concrete struct:
//
//	{"kind": <byte>, "body": { ...struct fields... }}
//
// This is the wire shape for gasoctl (unix socket); the transport
// just frames lines (one JSON object per line).
type Envelope struct {
	Kind Kind            `json:"kind"`
	Body json.RawMessage `json:"body,omitempty"`
}

// MarshalJSON encodes op into the JSON envelope above.
func MarshalJSON(op Op) ([]byte, error) {
	if op == nil {
		return nil, fmt.Errorf("control: nil op")
	}
	body, err := json.Marshal(op)
	if err != nil {
		return nil, fmt.Errorf("control: marshal %T: %w", op, err)
	}
	return json.Marshal(Envelope{Kind: op.Kind(), Body: body})
}

// UnmarshalJSON parses an envelope and returns a populated Op.
// Unknown Kind values are reported as an error.
func UnmarshalJSON(b []byte) (Op, error) {
	var env Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, fmt.Errorf("control: envelope: %w", err)
	}
	op := New(env.Kind)
	if op == nil {
		return nil, fmt.Errorf("control: unknown kind %#x", byte(env.Kind))
	}
	if len(env.Body) > 0 {
		if err := json.Unmarshal(env.Body, op); err != nil {
			return nil, fmt.Errorf("control: body kind %#x: %w", byte(env.Kind), err)
		}
	}
	return op, nil
}
