package operator

import (
	"net/netip"
	"sync"
	"time"
)

// OperatorEntry represents a remote operator node in the cluster.
type OperatorEntry struct {
	Addr     string        // ip:port of the remote operator
	PingCost time.Duration // measured network latency to this operator
	LastPing time.Time     // last time ping was measured
}

// SessionEntry represents a client session within a VNet.
type SessionEntry struct {
	OperatorID OperatorUUIDType // UUID of the operator this client is connected to
	IP         netip.Addr       // assigned IP of the client
	AllowedIPs []netip.Prefix   // allowed IP ranges for this client
}

// VNetEntry represents a virtual network group.
type VNetEntry struct {
	mu       sync.RWMutex
	Sessions map[SessionIDType]*SessionEntry // session ID -> session entry
}

func NewVNetEntry() *VNetEntry {
	return &VNetEntry{
		Sessions: make(map[SessionIDType]*SessionEntry),
	}
}

func (v *VNetEntry) AddSession(sessionID SessionIDType, entry *SessionEntry) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.Sessions[sessionID] = entry
}

func (v *VNetEntry) RemoveSession(sessionID SessionIDType) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.Sessions, sessionID)
}

func (v *VNetEntry) GetSession(sessionID SessionIDType) (*SessionEntry, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	s, ok := v.Sessions[sessionID]
	return s, ok
}

// Registry holds the operator cluster map and the client access table.
type Registry struct {
	opMu        sync.RWMutex
	OperatorMap map[OperatorUUIDType]*OperatorEntry // operator UUID -> entry

	clientMu  sync.RWMutex
	ClientMap map[VNetIDType]*VNetEntry // vnet ID -> vnet entry
}

func NewRegistry() *Registry {
	return &Registry{
		OperatorMap: make(map[OperatorUUIDType]*OperatorEntry),
		ClientMap:   make(map[VNetIDType]*VNetEntry),
	}
}

// --- OperatorMap operations ---

func (r *Registry) SetOperator(uuid OperatorUUIDType, entry *OperatorEntry) {
	r.opMu.Lock()
	defer r.opMu.Unlock()
	r.OperatorMap[uuid] = entry
}

func (r *Registry) GetOperator(uuid OperatorUUIDType) (*OperatorEntry, bool) {
	r.opMu.RLock()
	defer r.opMu.RUnlock()
	e, ok := r.OperatorMap[uuid]
	return e, ok
}

func (r *Registry) RemoveOperator(uuid OperatorUUIDType) {
	r.opMu.Lock()
	defer r.opMu.Unlock()
	delete(r.OperatorMap, uuid)
}

// --- ClientMap operations ---

func (r *Registry) GetOrCreateVNet(vnetID VNetIDType) *VNetEntry {
	r.clientMu.Lock()
	defer r.clientMu.Unlock()
	if v, ok := r.ClientMap[vnetID]; ok {
		return v
	}
	v := NewVNetEntry()
	r.ClientMap[vnetID] = v
	return v
}

func (r *Registry) GetVNet(vnetID VNetIDType) (*VNetEntry, bool) {
	r.clientMu.RLock()
	defer r.clientMu.RUnlock()
	v, ok := r.ClientMap[vnetID]
	return v, ok
}

func (r *Registry) RemoveVNet(vnetID VNetIDType) {
	r.clientMu.Lock()
	defer r.clientMu.Unlock()
	delete(r.ClientMap, vnetID)
}
