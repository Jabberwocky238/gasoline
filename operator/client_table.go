package operator

import (
	"github.com/jabberwocky238/gasoline/common"
)

// vniVMACKey indexes the ClientTable by (VNI, VMAC).
type vniVMACKey struct {
	vni common.VNI
	cid common.VMAC
}

// clientTableState is the guarded inner state.
type clientTableState struct {
	byVMAC map[vniVMACKey]*ClientPeer
}

// ClientTable manages connected client peers indexed by (VNI, VMAC) — the
// forwarding identity used by the data plane. IP-based lookup was removed:
// the data plane never inspects inner IP payloads, and overlapping VNet CIDRs
// make IP a non-unique key.
type ClientTable struct {
	guard *common.MutexGuard[clientTableState]
}

func NewClientTable() *ClientTable {
	return &ClientTable{
		guard: common.WithGuard(clientTableState{
			byVMAC: make(map[vniVMACKey]*ClientPeer),
		}),
	}
}

func (ct *ClientTable) Add(cp *ClientPeer) {
	ct.guard.Write(func(s *clientTableState) {
		s.byVMAC[vniVMACKey{cp.VNI, cp.VMAC}] = cp
	})
}

func (ct *ClientTable) Remove(cp *ClientPeer) {
	ct.guard.Write(func(s *clientTableState) {
		key := vniVMACKey{cp.VNI, cp.VMAC}
		if existing, ok := s.byVMAC[key]; ok && existing == cp {
			delete(s.byVMAC, key)
		}
	})
}

// LookupByVMAC finds a client peer by (VNI, VMAC) — used by the data plane to
// forward without inspecting inner IP payloads.
func (ct *ClientTable) LookupByVMAC(vni common.VNI, cid common.VMAC) *ClientPeer {
	var out *ClientPeer
	ct.guard.Read(func(s clientTableState) {
		out = s.byVMAC[vniVMACKey{vni, cid}]
	})
	return out
}

// Snapshot returns a copy of all currently registered peers.
func (ct *ClientTable) Snapshot() []*ClientPeer {
	var out []*ClientPeer
	ct.guard.Read(func(s clientTableState) {
		out = make([]*ClientPeer, 0, len(s.byVMAC))
		for _, cp := range s.byVMAC {
			out = append(out, cp)
		}
	})
	return out
}

func (ct *ClientTable) Len() int {
	var n int
	ct.guard.Read(func(s clientTableState) { n = len(s.byVMAC) })
	return n
}

func (ct *ClientTable) CloseAll() {
	peers := ct.Snapshot()
	for _, cp := range peers {
		_ = cp.Conn.Close()
	}
}
