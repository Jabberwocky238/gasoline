package operator

import (
	"errors"
	"net/netip"
	"time"

	"github.com/jabberwocky238/gasoline/cmd/operator/device/consensus"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/assign"
	"github.com/jabberwocky238/gasoline/protocol/noise"
)

// raftAllocator is the consensus-backed assign.Allocator (PRD §2.3 / §4). It
// picks a free IP from the local FSM replica optimistically, then commits the
// (IP, SessionID) pair through Raft at Confirm time. A commit-time collision
// (another node took the IP first) is surfaced as assign.ErrIPConflict so the
// assign server retries with a fresh pick.
type raftAllocator struct {
	node     *consensus.Node
	state    *operatorState
	leaseTTL time.Duration
	self     [16]byte // this operator's UUID (LastOperator at creation)
	timeout  time.Duration
}

func (a *raftAllocator) Preclaim(vni protocol.VNI_Ty, pubkey noise.PublicKey) (assign.Reservation, assign.Code) {
	ip, ranges, ok := a.node.PickIP(vni, pubkey)
	if !ok {
		return assign.Reservation{}, assign.CodeNoRoute
	}
	return assign.Reservation{
		IP:        ip,
		Ranges:    ranges,
		SessionID: protocol.NewSessionID(),
	}, assign.CodeOK
}

func (a *raftAllocator) Confirm(vni protocol.VNI_Ty, pubkey noise.PublicKey, r assign.Reservation) error {
	err := a.node.CommitSession(&consensus.SessionCreate{
		SessionID: r.SessionID,
		PubKey:    pubkey,
		VNI:       vni,
		IP:        r.IP,
		Operator:  a.self,
		LeaseTTL:  a.leaseTTL,
		Now:       time.Now().UnixNano(),
	}, a.timeout)
	if err != nil {
		if errors.Is(err, consensus.ErrIPTaken) {
			return assign.ErrIPConflict
		}
		return err
	}
	// Committed cluster-wide. Install the local forwarding entry so packets to
	// this IP reach the client's connection (keyed by SessionID).
	if vn, ok := a.state.vni(vni); ok {
		vn.routingMap.SetClient(r.SessionID, netip.PrefixFrom(r.IP, r.IP.BitLen()))
	}
	return nil
}

// Rollback is a no-op: Preclaim performed no durable write (the SessionID was
// only minted locally; nothing was proposed to Raft until Confirm).
func (a *raftAllocator) Rollback(vni protocol.VNI_Ty, r assign.Reservation) {}
