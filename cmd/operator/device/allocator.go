package operator

import (
	"net/netip"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/assign"
	"github.com/jabberwocky238/gasoline/protocol/noise"
)

// localAllocator is the pre-Raft assign.Allocator. Preclaim resolves the fixed
// IP for a pubkey (PRD §4.5 preset/lock) and mints a SessionID; Confirm writes
// the sessionID->prefix route so forwardFrame can reach the client. The
// Raft-backed pool with real reservation state lands in P4.
type localAllocator struct {
	state *operatorState
}

func (a *localAllocator) Preclaim(vni protocol.VNI_Ty, pubkey noise.PublicKey) (assign.Reservation, assign.Code) {
	vn, ok := a.state.vni(vni)
	if !ok {
		return assign.Reservation{}, assign.CodeNoRoute
	}
	vn.mu.RLock()
	pfx, ok := vn.presetIP[pubkey]
	vn.mu.RUnlock()
	if !ok {
		// No fixed IP for this key; dynamic pool allocation is P4.
		return assign.Reservation{}, assign.CodeNoRoute
	}
	return assign.Reservation{
		IP:        pfx.Addr(),
		Ranges:    a.state.cidrs[vni],
		SessionID: protocol.NewSessionID(),
	}, assign.CodeOK
}

// Confirm binds sessionID -> the client's /32 in the routing table, making the
// client reachable. (The preset already fixed the IP; here we install the
// forwarding entry keyed by the freshly minted SessionID.)
func (a *localAllocator) Confirm(vni protocol.VNI_Ty, r Reservation) {
	vn, ok := a.state.vni(vni)
	if !ok {
		return
	}
	vn.routingMap.SetClient(r.SessionID, netip.PrefixFrom(r.IP, r.IP.BitLen()))
}

// Rollback is a no-op for the preset-backed allocator: nothing is reserved
// (the IP is static), and Confirm hasn't written the route yet. Raft-backed
// allocation makes this meaningful.
func (a *localAllocator) Rollback(vni protocol.VNI_Ty, r Reservation) {}

// Reservation aliases assign.Reservation for the method receivers above.
type Reservation = assign.Reservation
