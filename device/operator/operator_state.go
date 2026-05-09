package operator

import (
	"context"
	"fmt"
	"sync"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
)

// operatorState owns every VNI's runtime entry plus the peer-operator
// table. vniEntry rows are created up-front from the static config; we
// don't admit clients for unknown VNIs.
type operatorState struct {
	ctx context.Context

	mu    sync.RWMutex
	vnets map[protocol.VNI_Ty]*vniEntry
	Peers *PeerOperatorTable
}

func newOperatorState(ctx context.Context) *operatorState {
	return &operatorState{
		ctx:   ctx,
		vnets: make(map[protocol.VNI_Ty]*vniEntry),
		Peers: NewPeerTable(),
	}
}

func (s *operatorState) registerVNI(vni protocol.VNI_Ty, authn auth.ServerAuthenticator, pool *VNetIpPool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vnets[vni] = newVniEntry(authn, pool)
}

func (s *operatorState) vni(vni protocol.VNI_Ty) (*vniEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.vnets[vni]
	return v, ok
}

func (s *operatorState) addClient(cp *PeerClient) (*vniEntry, error) {
	v, ok := s.vni(cp.VNI)
	if !ok {
		return nil, fmt.Errorf("unknown vni %d", cp.VNI)
	}
	v.addClient(cp)
	return v, nil
}

func (s *operatorState) removeClient(cp *PeerClient) {
	v, ok := s.vni(cp.VNI)
	if !ok {
		return
	}
	v.removeClient(cp.SessionIndex)
}

func (s *operatorState) totalClients() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, v := range s.vnets {
		v.mu.RLock()
		n += len(v.clients)
		v.mu.RUnlock()
	}
	return n
}

func (s *operatorState) snapshot() []*PeerClient {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*PeerClient
	for _, v := range s.vnets {
		out = append(out, v.Clients()...)
	}
	return out
}

func (s *operatorState) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.vnets {
		for _, cp := range v.Clients() {
			_ = cp.Conn.Close()
		}
		v.clients = make(map[uint32]*PeerClient)
	}
}
