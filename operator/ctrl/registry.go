package ctrl

import (
	"net/netip"
	"sync"
	"time"

	"github.com/jabberwocky238/gasoline/common"
)

// VNetSessions lives in vni-table.go — O(1) triple-indexed session table.

type OperatorInfo struct {
	Addr     string
	PingCost time.Duration
	LastPing time.Time
}

type SessionInfo struct {
	OperatorUUID [16]byte
	VMAC         common.VMAC
	IP           netip.Addr
}

// Registry holds cluster state: known operators and remote sessions.
type Registry struct {
	opMu      sync.RWMutex
	operators map[[16]byte]*OperatorInfo

	vnetMu sync.RWMutex
	vnets  map[common.VNI]*VNetSessions
}

func NewRegistry() *Registry {
	return &Registry{
		operators: make(map[[16]byte]*OperatorInfo),
		vnets:     make(map[common.VNI]*VNetSessions),
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

func (r *Registry) GetOrCreateVNet(vni common.VNI) *VNetSessions {
	r.vnetMu.Lock()
	defer r.vnetMu.Unlock()
	if v, ok := r.vnets[vni]; ok {
		return v
	}
	v := newVNetSessions()
	r.vnets[vni] = v
	return v
}

func (r *Registry) GetVNet(vni common.VNI) (*VNetSessions, bool) {
	r.vnetMu.RLock()
	defer r.vnetMu.RUnlock()
	v, ok := r.vnets[vni]
	return v, ok
}
