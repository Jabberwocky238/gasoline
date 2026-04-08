package ctrl

import (
	"net/netip"
	"sync"
	"time"
)

type OperatorInfo struct {
	Addr     string
	PingCost time.Duration
	LastPing time.Time
}

type SessionInfo struct {
	OperatorUUID [16]byte
	IP           netip.Addr
}

type VNetSessions struct {
	mu       sync.RWMutex
	Sessions map[[16]byte]*SessionInfo // sessionID -> info
}

func newVNetSessions() *VNetSessions {
	return &VNetSessions{Sessions: make(map[[16]byte]*SessionInfo)}
}

func (v *VNetSessions) Add(sessionID [16]byte, info *SessionInfo) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.Sessions[sessionID] = info
}

func (v *VNetSessions) Remove(sessionID [16]byte) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.Sessions, sessionID)
}

func (v *VNetSessions) Get(sessionID [16]byte) (*SessionInfo, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	s, ok := v.Sessions[sessionID]
	return s, ok
}

// LookupByIP finds a session matching the given IP address.
func (v *VNetSessions) LookupByIP(ip netip.Addr) (operatorUUID [16]byte, found bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, s := range v.Sessions {
		if s.IP == ip {
			return s.OperatorUUID, true
		}
	}
	return [16]byte{}, false
}

// Registry holds cluster state: known operators and remote sessions.
type Registry struct {
	opMu      sync.RWMutex
	operators map[[16]byte]*OperatorInfo

	vnetMu sync.RWMutex
	vnets  map[[16]byte]*VNetSessions // vnetID -> sessions
}

func NewRegistry() *Registry {
	return &Registry{
		operators: make(map[[16]byte]*OperatorInfo),
		vnets:     make(map[[16]byte]*VNetSessions),
	}
}

func (r *Registry) SetOperator(uuid [16]byte, info *OperatorInfo) {
	r.opMu.Lock()
	defer r.opMu.Unlock()
	r.operators[uuid] = info
}

func (r *Registry) GetOperator(uuid [16]byte) (*OperatorInfo, bool) {
	r.opMu.RLock()
	defer r.opMu.RUnlock()
	e, ok := r.operators[uuid]
	return e, ok
}

func (r *Registry) AllOperators() map[[16]byte]*OperatorInfo {
	r.opMu.RLock()
	defer r.opMu.RUnlock()
	m := make(map[[16]byte]*OperatorInfo, len(r.operators))
	for k, v := range r.operators {
		m[k] = v
	}
	return m
}

func (r *Registry) GetOrCreateVNet(vnetID [16]byte) *VNetSessions {
	r.vnetMu.Lock()
	defer r.vnetMu.Unlock()
	if v, ok := r.vnets[vnetID]; ok {
		return v
	}
	v := newVNetSessions()
	r.vnets[vnetID] = v
	return v
}

func (r *Registry) GetVNet(vnetID [16]byte) (*VNetSessions, bool) {
	r.vnetMu.RLock()
	defer r.vnetMu.RUnlock()
	v, ok := r.vnets[vnetID]
	return v, ok
}
