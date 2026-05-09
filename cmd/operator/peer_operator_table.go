package operator

import (
	"sync"
)

// PeerOperatorTable indexes peers by UUID.
type PeerOperatorTable struct {
	mu    sync.RWMutex
	peers map[[16]byte]*PeerOperator
}

func NewPeerTable() *PeerOperatorTable {
	return &PeerOperatorTable{peers: make(map[[16]byte]*PeerOperator)}
}

func (t *PeerOperatorTable) Add(p *PeerOperator) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.peers[p.UUID] = p
}

func (t *PeerOperatorTable) Remove(uuid [16]byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.peers, uuid)
}

func (t *PeerOperatorTable) Get(uuid [16]byte) (*PeerOperator, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	p, ok := t.peers[uuid]
	return p, ok
}

func (t *PeerOperatorTable) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.peers)
}

func (t *PeerOperatorTable) All() []*PeerOperator {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]*PeerOperator, 0, len(t.peers))
	for _, p := range t.peers {
		out = append(out, p)
	}
	return out
}
