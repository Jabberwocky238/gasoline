package operator

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/noise"
)

// nextSessionIndex issues a fresh per-session index.
func (s *operatorState) nextSessionIndex() uint32 { return s.sessionIndexSeq.Add(1) }

type Ctrl interface {
	Start() error
	Close() error
}

// ClientEventFn is invoked whenever a client attaches to or detaches
// from any VNI on this operator. attached==false means the client
// just left.
type ClientEventFn func(vni protocol.VNI_Ty, sid protocol.SessionID_Ty, prefix netip.Prefix, attached bool)

// operatorState owns every VNI's runtime entry plus the peer-operator
// table. vniEntry rows are created up-front from the static config; we
// don't admit clients for unknown VNIs.
type operatorState struct {
	lctx *common.LogContext
	mu   sync.RWMutex

	ctrls map[string]Ctrl
	vnets map[protocol.VNI_Ty]*vniEntry
	Peers *PeerTable

	// uuid of the local operator (mirrored from Operator.uuid).
	uuid [16]byte

	// Noise static key pair for the operator (responder side of handshakes).
	staticPriv noise.PrivateKey
	staticPub  noise.PublicKey

	// cidrs maps VNI -> its CIDR, populated at construction. Used by the
	// assign allocator to report IPRanges to clients.
	cidrs map[protocol.VNI_Ty]netip.Prefix

	// sessionIndexSeq issues per-session indices used in packet headers.
	sessionIndexSeq atomic.Uint32

	subMu  sync.Mutex
	subs   []ClientEventFn
	subSeq uint64
}

func newOperatorState(parent *common.LogContext) *operatorState {
	return &operatorState{
		lctx:  parent.Derive(),
		ctrls: make(map[string]Ctrl),
		vnets: make(map[protocol.VNI_Ty]*vniEntry),
		Peers: NewPeerTable(),
	}
}

// SubscribeClientEvents registers fn to receive every subsequent
// client attach/detach. Returns an unsubscribe func.
func (s *operatorState) SubscribeClientEvents(fn ClientEventFn) (unsubscribe func()) {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	idx := len(s.subs)
	s.subs = append(s.subs, fn)
	return func() {
		s.subMu.Lock()
		defer s.subMu.Unlock()
		if idx < len(s.subs) {
			s.subs[idx] = nil
		}
	}
}

func (s *operatorState) emitClientEvent(vni protocol.VNI_Ty, sid protocol.SessionID_Ty, prefix netip.Prefix, attached bool) {
	s.subMu.Lock()
	subs := append([]ClientEventFn(nil), s.subs...)
	s.subMu.Unlock()
	for _, fn := range subs {
		if fn != nil {
			fn(vni, sid, prefix, attached)
		}
	}
}

func (s *operatorState) registerVNI(vni protocol.VNI_Ty, authorizedKeys map[noise.PublicKey]struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := newVniEntry(authorizedKeys)
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
	v, ok := s.vni(cp.sc.VNI)
	if !ok {
		return nil, fmt.Errorf("unknown vni %s", cp.sc.VNI)
	}
	v.addClient(cp)
	pfx, _ := v.routingMap.LookupBySessionID(cp.sc.SessionID)
	s.emitClientEvent(cp.sc.VNI, cp.sc.SessionID, pfx, true)
	return v, nil
}

func (s *operatorState) removeClient(cp *PeerClient) {
	v, ok := s.vni(cp.sc.VNI)
	if !ok {
		return
	}
	pfx, _ := v.routingMap.LookupBySessionID(cp.sc.SessionID)
	v.removeClient(cp.sc.SessionIndex)
	s.emitClientEvent(cp.sc.VNI, cp.sc.SessionID, pfx, false)
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

func (s *operatorState) routeSet(sid protocol.SessionID_Ty, prefix netip.Prefix) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.vnets) == 0 {
		return fmt.Errorf("no vnets configured")
	}
	for _, v := range s.vnets {
		v.routingMap.SetClient(sid, prefix)
	}
	return nil
}

func (s *operatorState) routeGet(sid protocol.SessionID_Ty) (netip.Prefix, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, v := range s.vnets {
		if pfx, ok := v.routingMap.LookupBySessionID(sid); ok {
			return pfx, true
		}
	}
	return netip.Prefix{}, false
}

func (s *operatorState) routeDel(sid protocol.SessionID_Ty) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, v := range s.vnets {
		v.routingMap.DeleteBySessionID(sid)
	}
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
