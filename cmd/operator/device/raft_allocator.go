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

// raftAllocator is the consensus-backed datacom.Allocator (PRD §2.3, post-2PC).
// It commits the session through Raft in one shot; the leader's Apply allocates
// a free IP deterministically (first-free) and returns it — no pre-selection,
// no collision, no retry.
type raftAllocator struct {
	node     *consensus.Node
	state    *operatorState
	leaseTTL time.Duration
	self     [16]byte // this operator's UUID (LastOperator at creation)
	timeout  time.Duration
}

// Assign commits SessionCreate and returns the leader-allocated IP. On pool
// exhaustion (consensus.ErrNoAddress) it reports CodeNoRoute.
func (a *raftAllocator) Assign(vni protocol.VNI_Ty, pubkey noise.PublicKey, sessionID protocol.SessionID_Ty, keys datacom.DataKeys) (netip.Addr, netip.Prefix, datacom.Code) {
	ip, ranges, err := a.node.CommitSession(&consensus.SessionCreate{
		SessionID: sessionID,
		PubKey:    pubkey,
		VNI:       vni,
		C2SKey:    keys.C2SKey,
		S2CKey:    keys.S2CKey,
		Operator:  a.self,
		LeaseTTL:  a.leaseTTL,
		Now:       time.Now().UnixNano(),
	}, a.timeout)
	if err != nil {
		if errors.Is(err, consensus.ErrNoAddress) {
			return netip.Addr{}, netip.Prefix{}, datacom.CodeNoRoute
		}
		// A transport / leader-unreachable error also has no address to hand out.
		return netip.Addr{}, netip.Prefix{}, datacom.CodeNoRoute
	}
	// Committed cluster-wide. Install the local forwarding entry so packets to
	// this IP reach the client's connection (keyed by SessionID).
	if vn, ok := a.state.vni(vni); ok {
		vn.routingMap.SetClient(sessionID, netip.PrefixFrom(ip, ip.BitLen()))
	}
	return ip, ranges, datacom.CodeOK
}
