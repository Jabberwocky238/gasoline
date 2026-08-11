package operator

import (
	"errors"
	"net/netip"
	"time"

	"github.com/jabberwocky238/gasoline/cmd/operator/device/consensus"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/datacom"
	"github.com/jabberwocky238/gasoline/protocol/noise"
)

// raftAllocator is the consensus-backed datacom.Allocator (PRD §2.3 / §4). It
// picks a free IP from the local FSM replica optimistically, then commits the
// (IP, SessionID) pair through Raft at Confirm time. A commit-time collision
// (another node took the IP first) is surfaced as datacom.ErrIPConflict so the
// assign server retries with a fresh pick.
type raftAllocator struct {
	node     *consensus.Node
	state    *operatorState
	leaseTTL time.Duration
	self     [16]byte // this operator's UUID (LastOperator at creation)
	timeout  time.Duration
}

func (a *raftAllocator) Preclaim(vni protocol.VNI_Ty, pubkey noise.PublicKey) (datacom.Reservation, datacom.Code) {
	ip, ranges, ok := a.node.PickIP(vni, pubkey)
	if !ok {
		return datacom.Reservation{}, datacom.CodeNoRoute
	}
	return datacom.Reservation{
		IP:        ip,
		Ranges:    ranges,
		SessionID: protocol.NewSessionID(),
	}, datacom.CodeOK
}

func (a *raftAllocator) Confirm(vni protocol.VNI_Ty, pubkey noise.PublicKey, r datacom.Reservation) error {
	err := a.node.CommitSession(&consensus.SessionCreate{
		SessionID: r.SessionID,
		PubKey:    pubkey,
		VNI:       vni,
		IP:        r.IP,
		C2SKey:    r.Keys.C2SKey,
		S2CKey:    r.Keys.S2CKey,
		Operator:  a.self,
		LeaseTTL:  a.leaseTTL,
		Now:       time.Now().UnixNano(),
	}, a.timeout)
	if err != nil {
		if errors.Is(err, consensus.ErrIPTaken) {
			return datacom.ErrIPConflict
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
func (a *raftAllocator) Rollback(vni protocol.VNI_Ty, r datacom.Reservation) {}
