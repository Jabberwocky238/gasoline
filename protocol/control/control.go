// Package control defines the unified vocabulary used by both
// gasoctl (operator IPC) and the operator <-> cordinator wire. Each
// operation has its own struct file in this package.
//
// The list of operations is finite and intentionally small:
//
//	RouteUpsert / RouteRemove / RouteQuery
//	PeerJoin / PeerLeave
//	CordinatorConnect / CordinatorDisconnect
//	Reply (OK / Err)
//
// Encoding/transport (line text, JSON, etc.) is the caller's choice;
// this package only owns the parameter shapes.
package control

// Op is the union over all operation kinds defined in this package.
// Every concrete Op exposes:
//
//	Kind()          // 1-byte type tag
//	Encode() []byte // self-contained big-endian binary form
//	Decode([]byte)  // inverse of Encode
//
// The Kind tag is NOT included in Encode's output; transports that
// need to dispatch polymorphically prepend it themselves (or wrap in
// a frame).
type Op interface {
	opMarker()
	Kind() Kind
	Encode() []byte
	Decode([]byte) error
}

// Kind is a 1-byte discriminator. Values are stable across versions.
type Kind uint8

const (
	KindUnknown                Kind = 0x00
	KindRouteUpsert            Kind = 0x01
	KindRouteRemove            Kind = 0x02
	KindRouteQuery             Kind = 0x03
	KindPeerJoin               Kind = 0x10
	KindPeerLeave              Kind = 0x11
	KindCordinatorConnect      Kind = 0x20
	KindCordinatorConnectReply Kind = 0x22
	KindCordinatorDisconnect   Kind = 0x21
	KindReply                  Kind = 0xF0
)

// New returns a zero-valued Op for the given kind, ready to receive a
// Decode call. Returns nil for unknown kinds.
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
	case KindCordinatorConnect:
		return &CordinatorConnect{}
	case KindCordinatorConnectReply:
		return &CordinatorConnectReply{}
	case KindCordinatorDisconnect:
		return &CordinatorDisconnect{}
	case KindReply:
		return &Reply{}
	}
	return nil
}
