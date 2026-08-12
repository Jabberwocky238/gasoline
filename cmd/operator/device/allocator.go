package operator

import (
	"net/netip"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/datacom"
	"github.com/jabberwocky238/gasoline/protocol/noise"
)

// localAllocator is the pre-Raft datacom.Allocator: it resolves the fixed IP for
// a pubkey (PRD §4.5 preset/lock) and binds sessionID -> that /32 in the routing
// table so forwardFrame can reach the client. Single operator, no consensus, no
// pool — used only when Raft is not attached.
type localAllocator struct {
	state *operatorState
}

// Assign resolves the preset fixed IP for pubkey and installs its route. Keys
// are not persisted (no Raft; the live noise.Session on the conn handles crypto
// for this single-operator path).
func (a *localAllocator) Assign(vni protocol.VNI_Ty, pubkey noise.PublicKey, sessionID protocol.SessionID_Ty, _ datacom.DataKeys) (netip.Addr, netip.Prefix, datacom.Code) {
	vn, ok := a.state.vni(vni)
	if !ok {
		return netip.Addr{}, netip.Prefix{}, datacom.CodeNoRoute
	}
	vn.mu.RLock()
	pfx, ok := vn.presetIP[pubkey]
	vn.mu.RUnlock()
	if !ok {
		return netip.Addr{}, netip.Prefix{}, datacom.CodeNoRoute
	}
	ip := pfx.Addr()
	vn.routingMap.SetClient(sessionID, netip.PrefixFrom(ip, ip.BitLen()))
	return ip, a.state.cidrs[vni], datacom.CodeOK
}
