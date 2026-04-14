package operator

import (
	"net/netip"
	"sync"

	"github.com/jabberwocky238/gasoline/common"
)

// vniCIDKey indexes the ClientTable by (VNI, ClientID).
type vniCIDKey struct {
	vni common.VNI
	cid common.ClientID
}

// ClientTable manages connected client peers with dual indexes:
//   - by assigned IP (for ingress translation)
//   - by (VNI, ClientID) (for data-plane forwarding without IP parsing)
type ClientTable struct {
	mu    sync.RWMutex
	byIP  map[netip.Addr]*ClientPeer
	byCID map[vniCIDKey]*ClientPeer
}

func NewClientTable() *ClientTable {
	return &ClientTable{
		byIP:  make(map[netip.Addr]*ClientPeer),
		byCID: make(map[vniCIDKey]*ClientPeer),
	}
}

func (ct *ClientTable) Add(cp *ClientPeer) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.byIP[cp.IP.Addr()] = cp
	ct.byCID[vniCIDKey{cp.VNI, cp.ClientID}] = cp
}

func (ct *ClientTable) Remove(cp *ClientPeer) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	addr := cp.IP.Addr()
	if existing, ok := ct.byIP[addr]; ok && existing == cp {
		delete(ct.byIP, addr)
	}
	key := vniCIDKey{cp.VNI, cp.ClientID}
	if existing, ok := ct.byCID[key]; ok && existing == cp {
		delete(ct.byCID, key)
	}
}

// LookupByIP finds a client peer by exact assigned IP match.
func (ct *ClientTable) LookupByIP(addr netip.Addr) *ClientPeer {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.byIP[addr]
}

// LookupByCID finds a client peer by (VNI, ClientID) — used by the data
// plane to forward without inspecting inner IP payloads.
func (ct *ClientTable) LookupByCID(vni common.VNI, cid common.ClientID) *ClientPeer {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.byCID[vniCIDKey{vni, cid}]
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
