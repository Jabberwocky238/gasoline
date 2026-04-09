package operator

import (
	"net/netip"
	"sync"
)

// ClientTable manages connected client peers indexed by assigned IP.
type ClientTable struct {
	mu    sync.RWMutex
	peers map[netip.Addr]*ClientPeer
}

func NewClientTable() *ClientTable {
	return &ClientTable{
		peers: make(map[netip.Addr]*ClientPeer),
	}
}

func (ct *ClientTable) Add(cp *ClientPeer) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.peers[cp.IP.Addr()] = cp
}

func (ct *ClientTable) Remove(cp *ClientPeer) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	addr := cp.IP.Addr()
	if existing, ok := ct.peers[addr]; ok && existing == cp {
		delete(ct.peers, addr)
	}
}

// LookupByIP finds a client peer by exact assigned IP match.
func (ct *ClientTable) LookupByIP(addr netip.Addr) *ClientPeer {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.peers[addr]
}

func (ct *ClientTable) Len() int {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return len(ct.peers)
}

func (ct *ClientTable) CloseAll() {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	for _, cp := range ct.peers {
		cp.Conn.Close()
	}
}
