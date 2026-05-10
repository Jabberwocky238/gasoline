package operator

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
)

type Ctrl interface {
	Start() error
	Close() error
}

// operatorState owns every VNI's runtime entry plus the peer-operator
// table. vniEntry rows are created up-front from the static config; we
// don't admit clients for unknown VNIs.
type operatorState struct {
	lctx *common.LogContext
	mu   sync.RWMutex

	ctrls map[string]Ctrl
	vnets map[protocol.VNI_Ty]*vniEntry
	Peers *PeerTable
}

func newOperatorState(parent *common.LogContext) *operatorState {
	return &operatorState{
		lctx:  parent.Derive(),
		ctrls: make(map[string]Ctrl),
		vnets: make(map[protocol.VNI_Ty]*vniEntry),
		Peers: NewPeerTable(),
	}
}

func (s *operatorState) registerVNI(vni protocol.VNI_Ty, authn auth.ServerAuthenticator) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := newVniEntry(authn)
	v.vni = vni
	v.peers = s.Peers
	s.vnets[vni] = v
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

// --------------- gasoctl-driven operations ---------------
//
// Route commands don't carry a VNI yet, so for now we apply set/del to
// every configured VNI's routingMap and walk every VNI on get. When
// the wire protocol grows a VNI field these collapse to one lookup.

func (s *operatorState) routeSet(cid protocol.CID_Ty, prefix netip.Prefix) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.vnets) == 0 {
		return fmt.Errorf("no vnets configured")
	}
	for _, v := range s.vnets {
		v.routingMap.Set(cid, prefix)
	}
	return nil
}

func (s *operatorState) routeGet(cid protocol.CID_Ty) (netip.Prefix, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, v := range s.vnets {
		if pfx, ok := v.routingMap.LookupByCID(cid); ok {
			return pfx, true
		}
	}
	return netip.Prefix{}, false
}

func (s *operatorState) routeDel(cid protocol.CID_Ty) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, v := range s.vnets {
		v.routingMap.DeleteByCID(cid)
	}
}

// cordinatorKey is the ctrls map key for a Cordinator targeting endpoint.
func cordinatorKey(endpoint string) string { return "cordinator:" + endpoint }

func (s *operatorState) cordinatorConnect(endpoint string) error {
	key := cordinatorKey(endpoint)

	s.mu.Lock()
	if _, dup := s.ctrls[key]; dup {
		s.mu.Unlock()
		return fmt.Errorf("cordinator: already connected to %s", endpoint)
	}
	s.mu.Unlock()

	cc, err := NewCordinator(s, endpoint)
	if err != nil {
		return err
	}
	if err := cc.Start(); err != nil {
		return err
	}

	s.mu.Lock()
	s.ctrls[key] = cc
	s.mu.Unlock()
	return nil
}

func (s *operatorState) cordinatorDisconnect(endpoint string) error {
	key := cordinatorKey(endpoint)

	s.mu.Lock()
	cc, ok := s.ctrls[key]
	if ok {
		delete(s.ctrls, key)
	}
	s.mu.Unlock()

	if !ok {
		return fmt.Errorf("cordinator: not connected to %s", endpoint)
	}
	return cc.Close()
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
