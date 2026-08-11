package operator

import (
	"net/netip"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/datacom"
	"github.com/jabberwocky238/gasoline/protocol/noise"
)

// localAllocator is the pre-Raft datacom.Allocator. Preclaim resolves the fixed
// IP for a pubkey (PRD §4.5 preset/lock) and mints a SessionID; Confirm writes
// the sessionID->prefix route so forwardFrame can reach the client. The
// Raft-backed pool with real reservation state lands in P4.
type localAllocator struct {
	state *operatorState
}

func (a *localAllocator) Preclaim(vni protocol.VNI_Ty, pubkey noise.PublicKey) (datacom.Reservation, datacom.Code) {
	vn, ok := a.state.vni(vni)
	if !ok {
		return datacom.Reservation{}, datacom.CodeNoRoute
	}
	vn.mu.RLock()
	pfx, ok := vn.presetIP[pubkey]
	vn.mu.RUnlock()
	if !ok {
		// No fixed IP for this key; dynamic pool allocation is P4.
		return datacom.Reservation{}, datacom.CodeNoRoute
	}
	return datacom.Reservation{
		IP:        pfx.Addr(),
		Ranges:    a.state.cidrs[vni],
		SessionID: protocol.NewSessionID(),
	}, datacom.CodeOK
}

// Confirm binds sessionID -> the client's /32 in the routing table, making the
// client reachable. The preset IP is static (no durable reservation), so
// Confirm never conflicts.
func (a *localAllocator) Confirm(vni protocol.VNI_Ty, _ noise.PublicKey, r datacom.Reservation) error {
	if vn, ok := a.state.vni(vni); ok {
		vn.routingMap.SetClient(r.SessionID, netip.PrefixFrom(r.IP, r.IP.BitLen()))
	}
	return nil
}

// Rollback is a no-op: Preclaim reserved nothing durable.
func (a *localAllocator) Rollback(vni protocol.VNI_Ty, r datacom.Reservation) {}
