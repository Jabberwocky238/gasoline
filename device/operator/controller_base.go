package operator

import (
	"fmt"

	"github.com/jabberwocky238/gasoline/protocol/control"
)

// ControllerBase is the shared dispatcher every controller (IPC,
// Cordinator, …) embeds. It holds a back-reference to the operator
// state and turns control.Op events into operator-state mutations.
//
// Consume is request/response shaped:
//   - For ops that are a query (RouteQuery), it returns a *Reply.
//   - For everything else it returns nil after applying the change.
//
// The mapping is intentionally one-way: encoding/transport details
// stay outside this file; controllers parse bytes, hand the typed Op
// to Consume, and (when non-nil) ship the Reply back over their wire.
type ControllerBase struct {
	state *operatorState
}

func newControllerBase(state *operatorState) ControllerBase {
	return ControllerBase{state: state}
}

// NewControllerBase returns a controller base wired to op's state.
// Each controller (IPC, Cordinator, …) accepts a *ControllerBase via
// its constructor; multiple bases over the same operator are
// equivalent (they all hold the same state pointer), so callers can
// freely build one per controller or share one across all of them.
func (o *Operator) NewControllerBase() *ControllerBase {
	b := newControllerBase(o.state)
	return &b
}

// Consume applies op against b.state and returns either a Reply (for
// request-shaped ops) or nil (for fire-and-forget events).
func (b *ControllerBase) Consume(op control.Op) control.Op {
	if op == nil || b.state == nil {
		return nil
	}
	switch v := op.(type) {

	case *control.RouteUpsert:
		vn, ok := b.state.vni(v.VNI)
		if !ok {
			return errReplyOp("unknown vni %s", v.VNI)
		}
		var zero [16]byte
		if v.OwnerUUID == zero || v.OwnerUUID == b.state.uuid {
			vn.routingMap.SetClient(v.CID, v.Prefix)
		} else {
			vn.routingMap.SetOperator(v.OwnerUUID, v.Prefix)
		}
		return nil

	case *control.RouteRemove:
		vn, ok := b.state.vni(v.VNI)
		if !ok {
			return nil
		}
		vn.routingMap.DeleteByCID(v.CID)
		return nil

	case *control.RouteQuery:
		vn, ok := b.state.vni(v.VNI)
		if !ok {
			return errReplyOp("unknown vni %s", v.VNI)
		}
		pfx, ok := vn.routingMap.LookupByCID(v.CID)
		if !ok {
			return errReplyOp("not found")
		}
		return &control.Reply{OK: true, Payload: pfx.String()}

	case *control.PeerJoin:
		if v.UUID != b.state.uuid {
			b.state.Peers.Add(NewPeerOperator(v.UUID, v.Endpoint))
		}
		return nil

	case *control.PeerLeave:
		b.state.Peers.Remove(v.UUID)
		return nil

	case *control.CordinatorConnect:
		if err := b.state.cordinatorConnect(v.Endpoint); err != nil {
			return &control.Reply{OK: false, Payload: err.Error()}
		}
		return &control.Reply{OK: true}

	case *control.CordinatorDisconnect:
		if err := b.state.cordinatorDisconnect(); err != nil {
			return &control.Reply{OK: false, Payload: err.Error()}
		}
		return &control.Reply{OK: true}

	case *control.CordinatorConnectReply:
		// Pre-load the peer table from the cordinator's snapshot.
		for i := range v.Peers {
			b.Consume(&v.Peers[i])
		}
		return nil
	}
	return nil
}

func errReplyOp(format string, args ...any) *control.Reply {
	if len(args) == 0 {
		return &control.Reply{OK: false, Payload: format}
	}
	return &control.Reply{OK: false, Payload: fmt.Sprintf(format, args...)}
}
