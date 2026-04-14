package operator

import (
	"net/netip"
	"sync"

	"github.com/jabberwocky238/gasoline/common"
)

// vniVMACKey indexes the ClientTable by (VNI, ClientID).
type vniVMACKey struct {
	vni common.VNI
	cid common.VMAC
}

// ClientTable manages connected client peers with dual indexes:
//   - by assigned IP (for ingress translation)
//   - by (VNI, ClientID) (for data-plane forwarding without IP parsing)
type ClientTable struct {
	mu    sync.RWMutex
	byIP  map[netip.Addr]*ClientPeer
	byVMAC map[vniVMACKey]*ClientPeer
}

func NewClientTable() *ClientTable {
	return &ClientTable{
		byIP:  make(map[netip.Addr]*ClientPeer),
		byVMAC: make(map[vniVMACKey]*ClientPeer),
	}
}

func (ct *ClientTable) Add(cp *ClientPeer) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.byIP[cp.IP.Addr()] = cp
	ct.byVMAC[vniVMACKey{cp.VNI, cp.VMAC}] = cp
}

func (ct *ClientTable) Remove(cp *ClientPeer) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	addr := cp.IP.Addr()
	if existing, ok := ct.byIP[addr]; ok && existing == cp {
		delete(ct.byIP, addr)
	}
	key := vniVMACKey{cp.VNI, cp.VMAC}
	if existing, ok := ct.byVMAC[key]; ok && existing == cp {
		delete(ct.byVMAC, key)
	}
}

// LookupByIP finds a client peer by exact assigned IP match.
func (ct *ClientTable) LookupByIP(addr netip.Addr) *ClientPeer {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.byIP[addr]
}

// LookupByVMAC finds a client peer by (VNI, ClientID) — used by the data
// plane to forward without inspecting inner IP payloads.
func (ct *ClientTable) LookupByVMAC(vni common.VNI, cid common.VMAC) *ClientPeer {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.byVMAC[vniVMACKey{vni, cid}]
}

func (ct *ClientTable) Len() int {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return len(ct.byIP)
}

func (ct *ClientTable) CloseAll() {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	for _, cp := range ct.byIP {
		cp.Conn.Close()
	}
}
