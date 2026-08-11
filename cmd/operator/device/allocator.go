package operator

import (
	"net/netip"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/assign"
	"github.com/jabberwocky238/gasoline/protocol/noise"
)

// localAllocator is the pre-Raft assign.Allocator: it resolves an address from
// the VNI's existing routing map (preset cid->prefix bindings). Preclaim is a
// pure lookup with no reservation state yet; Confirm/Rollback are no-ops. The
// Raft-backed pool with real two-phase reservation lands in P4 — this keeps the
// assign protocol exercised end to end in the meantime.
type localAllocator struct {
	state *operatorState
	cidrs map[protocol.VNI_Ty]netip.Prefix
}

func (a *localAllocator) Preclaim(vni protocol.VNI_Ty, cid protocol.CID_Ty, _ noise.PublicKey) (netip.Addr, netip.Prefix, assign.Code) {
	vn, ok := a.state.vni(vni)
	if !ok {
		return netip.Addr{}, netip.Prefix{}, assign.CodeNoRoute
	}
	pfx, ok := vn.routingMap.LookupByCID(cid)
	if !ok {
		return netip.Addr{}, netip.Prefix{}, assign.CodeNoRoute
	}
	return pfx.Addr(), a.cidrs[vni], assign.CodeOK
}

// Confirm / Rollback are no-ops for the preset-backed allocator: the binding is
// static, nothing is reserved. Raft-backed allocation makes these meaningful.
func (a *localAllocator) Confirm(protocol.VNI_Ty, protocol.CID_Ty, netip.Addr)  {}
func (a *localAllocator) Rollback(protocol.VNI_Ty, protocol.CID_Ty, netip.Addr) {}
