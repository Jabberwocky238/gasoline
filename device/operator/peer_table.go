package operator

import (
	"sync"
)

// PeerTable indexes peers by UUID.
type PeerTable struct {
	mu    sync.RWMutex
	peers map[[16]byte]*PeerOperator
}

func NewPeerTable() *PeerTable {
	return &PeerTable{peers: make(map[[16]byte]*PeerOperator)}
}

func (t *PeerTable) Add(p *PeerOperator) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.peers[p.UUID] = p
}

func (t *PeerTable) Remove(uuid [16]byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.peers, uuid)
}

func (t *PeerTable) Get(uuid [16]byte) (*PeerOperator, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	p, ok := t.peers[uuid]
	return p, ok
}

func (t *PeerTable) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.peers)
}

func (t *PeerTable) All() []*PeerOperator {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]*PeerOperator, 0, len(t.peers))
	for _, p := range t.peers {
		out = append(out, p)
	}
	return out
}
