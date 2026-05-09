package operator

import (
	"sync"

	"github.com/jabberwocky238/gasoline/protocol/auth"
)

// vniEntry holds per-VNI runtime state: the active client set, the
// authoritative cid<->prefix routing table, and its auth strategy.
type vniEntry struct {
	mu            sync.RWMutex
	authenticator auth.ServerAuthenticator
	clients       map[uint32]*PeerClient // keyed by SessionIndex
	routingMap    *vnetRoutingMap
}

func newVniEntry(authn auth.ServerAuthenticator) *vniEntry {
	return &vniEntry{
		authenticator: authn,
		clients:       make(map[uint32]*PeerClient),
		routingMap:    newVnetRoutingMap(),
	}
}

func (v *vniEntry) addClient(cp *PeerClient) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.clients[cp.SessionIndex] = cp
}

func (v *vniEntry) removeClient(sessionIndex uint32) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.clients, sessionIndex)
}

// Clients returns a snapshot copy of the per-VNI client set.
func (v *vniEntry) Clients() []*PeerClient {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]*PeerClient, 0, len(v.clients))
	for _, cp := range v.clients {
		out = append(out, cp)
	}
	return out
}

// peers returns every client *other* than the given session index.
// Used to broadcast a frame received from one client to the rest of the VNI.
func (v *vniEntry) peers(except uint32) []*PeerClient {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]*PeerClient, 0, len(v.clients))
	for idx, cp := range v.clients {
		if idx == except {
			continue
		}
		out = append(out, cp)
	}
	return out
}
