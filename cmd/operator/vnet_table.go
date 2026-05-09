package operator

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/jabberwocky238/gasoline/common"
)

// --------------- VNetTable ---------------

// VNetTable is a thread-safe registry of VNet pools keyed by VNI.
//
// The outer mutex only guards the map structure (Add / Remove / Get
// / iteration). Pool-state mutations — AllocateIP, ReleaseIP, … —
// happen inside each *VNetPool's own internal guard, so two VNIs
// never block each other on a hot path.
//
// Read paths (Get, AllocateIP-via-pool) take RLock on the outer
// mutex for an O(1) map lookup, then operate on the returned pool
// without holding it. Writes to the map (config reload) are rare.
type VNetTable struct {
	mu    sync.RWMutex
	pools map[common.VNI]*VNetPool
}

func NewVNetTable() *VNetTable {
	return &VNetTable{pools: make(map[common.VNI]*VNetPool)}
}

// ParseVNetPools parses "vni:CIDR;vni:CIDR;..." into a VNetTable.
// seed is used to spread starting offsets across operators (IPv4 only).
func ParseVNetPools(network string, seed uint32) (*VNetTable, error) {
	pools := make(map[common.VNI]*VNetPool)
	for _, entry := range strings.Split(network, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid network entry (expected vni:CIDR): %s", entry)
		}
		vni, err := common.ParseVNI(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid vni %q: %w", parts[0], err)
		}

		prefix, err := netip.ParsePrefix(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", parts[1], err)
		}

		pools[vni] = NewVNetPool(vni, prefix, seed)
	}
	return &VNetTable{pools: pools}, nil
}

// Get returns a pool by VNI. Read-only; safe for concurrent use.
func (m *VNetTable) Get(vni common.VNI) (*VNetPool, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.pools[vni]
	return p, ok
}

// Add inserts or replaces a pool for the given VNI.
func (m *VNetTable) Add(vni common.VNI, pool *VNetPool) {
	m.mu.Lock()
	m.pools[vni] = pool
	m.mu.Unlock()
}

// Remove deletes a pool by VNI. Returns true if it existed.
func (m *VNetTable) Remove(vni common.VNI) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, existed := m.pools[vni]
	delete(m.pools, vni)
	return existed
}

// All returns a snapshot of all pools for iteration.
func (m *VNetTable) All() map[common.VNI]*VNetPool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cp := make(map[common.VNI]*VNetPool, len(m.pools))
	for k, v := range m.pools {
		cp[k] = v
	}
	return cp
}

func addToAddrV4(base netip.Addr, offset uint32) netip.Addr {
	b4 := base.As4()
	val := uint32(b4[0])<<24 | uint32(b4[1])<<16 | uint32(b4[2])<<8 | uint32(b4[3])
	val += offset
	return netip.AddrFrom4([4]byte{byte(val >> 24), byte(val >> 16), byte(val >> 8), byte(val)})
}
