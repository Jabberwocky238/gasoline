package vxlan

import (
	"net"
	"sync"
	"time"

	"github.com/jabberwocky238/gasoline/common"
)

// vmacKey is the (VNI, VMAC) composite map key used by all internal indexes.
type vmacKey struct {
	vni common.VNI
	mac common.VMAC
}

// localEntry records a locally-attached port.
type localEntry struct {
	port  Port
	added time.Time
}

// remoteEntry records a learned remote operator endpoint.
type remoteEntry struct {
	addr     *net.UDPAddr
	lastSeen time.Time
}

// MACTable is the VXLAN plane's L2 forwarding database.
//
// It maintains two side-by-side indexes:
//
//	local  : (VNI, MAC) → Port           // locally-attached destinations
//	remote : (VNI, MAC) → *net.UDPAddr   // learned via inbound VXLAN frames
//
// A second pair of indexes (byVNI) supports flood operations efficiently.
//
// All methods are O(1) on the hot path and safe for concurrent use.
type MACTable struct {
	mu sync.RWMutex

	local  map[vmacKey]*localEntry
	remote map[vmacKey]*remoteEntry

	// Per-VNI sets used by Flood — kept in sync with local/remote.
	localByVNI  map[common.VNI]map[common.VMAC]Port
	remoteByVNI map[common.VNI]map[common.VMAC]*net.UDPAddr
}

func NewMACTable() *MACTable {
	return &MACTable{
		local:       make(map[vmacKey]*localEntry),
		remote:      make(map[vmacKey]*remoteEntry),
		localByVNI:  make(map[common.VNI]map[common.VMAC]Port),
		remoteByVNI: make(map[common.VNI]map[common.VMAC]*net.UDPAddr),
	}
}

// RegisterLocal binds a local Port for (VNI, MAC). Replaces any existing
// entry. Removes a stale remote entry for the same key if present (a MAC
// has migrated to be local).
func (t *MACTable) RegisterLocal(vni common.VNI, mac common.VMAC, port Port) {
	k := vmacKey{vni, mac}
	t.mu.Lock()
	defer t.mu.Unlock()

	t.local[k] = &localEntry{port: port, added: time.Now()}
	if _, ok := t.localByVNI[vni]; !ok {
		t.localByVNI[vni] = make(map[common.VMAC]Port)
	}
	t.localByVNI[vni][mac] = port

	if _, ok := t.remote[k]; ok {
		delete(t.remote, k)
		if m := t.remoteByVNI[vni]; m != nil {
			delete(m, mac)
		}
	}
}

// UnregisterLocal removes a local entry.
func (t *MACTable) UnregisterLocal(vni common.VNI, mac common.VMAC) {
	k := vmacKey{vni, mac}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.local, k)
	if m := t.localByVNI[vni]; m != nil {
		delete(m, mac)
		if len(m) == 0 {
			delete(t.localByVNI, vni)
		}
	}
}

// LearnRemote inserts/updates the remote entry for (VNI, MAC) → addr.
// Called by the Plane's RxLoop on every inbound VXLAN frame using the
// inner-frame's source MAC.
func (t *MACTable) LearnRemote(vni common.VNI, mac common.VMAC, addr *net.UDPAddr) {
	k := vmacKey{vni, mac}
	t.mu.Lock()
	defer t.mu.Unlock()

	// If the same MAC is locally attached, the local registration wins —
	// we don't learn a remote shadow that would shadow real local delivery.
	if _, isLocal := t.local[k]; isLocal {
		return
	}
	t.remote[k] = &remoteEntry{addr: addr, lastSeen: time.Now()}
	if _, ok := t.remoteByVNI[vni]; !ok {
		t.remoteByVNI[vni] = make(map[common.VMAC]*net.UDPAddr)
	}
	t.remoteByVNI[vni][mac] = addr
}

// ForgetRemote drops a remote entry (e.g. on session revoke).
func (t *MACTable) ForgetRemote(vni common.VNI, mac common.VMAC) {
	k := vmacKey{vni, mac}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.remote, k)
	if m := t.remoteByVNI[vni]; m != nil {
		delete(m, mac)
		if len(m) == 0 {
			delete(t.remoteByVNI, vni)
		}
	}
}

// LookupLocal returns the local Port for (VNI, MAC) or (nil, false).
func (t *MACTable) LookupLocal(vni common.VNI, mac common.VMAC) (Port, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.local[vmacKey{vni, mac}]
	if !ok {
		return nil, false
	}
	return e.port, true
}

// LookupRemote returns the learned UDP endpoint for (VNI, MAC) or (nil, false).
func (t *MACTable) LookupRemote(vni common.VNI, mac common.VMAC) (*net.UDPAddr, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.remote[vmacKey{vni, mac}]
	if !ok {
		return nil, false
	}
	return e.addr, true
}

// Lookup returns the first matching destination kind for (VNI, MAC):
//   - (port,    nil,  true)  → local
//   - (nil,     addr, true)  → remote
//   - (nil,     nil,  false) → unknown
func (t *MACTable) Lookup(vni common.VNI, mac common.VMAC) (Port, *net.UDPAddr, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if e, ok := t.local[vmacKey{vni, mac}]; ok {
		return e.port, nil, true
	}
	if e, ok := t.remote[vmacKey{vni, mac}]; ok {
		return nil, e.addr, true
	}
	return nil, nil, false
}

// LocalsInVNI returns a snapshot of all local (MAC → Port) entries in a VNI.
// Used by Flood.
func (t *MACTable) LocalsInVNI(vni common.VNI) map[common.VMAC]Port {
	t.mu.RLock()
	defer t.mu.RUnlock()
	src := t.localByVNI[vni]
	if len(src) == 0 {
		return nil
	}
	out := make(map[common.VMAC]Port, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// RemotesInVNI returns a snapshot of all remote (MAC → addr) entries in a VNI.
// Used by Flood.
func (t *MACTable) RemotesInVNI(vni common.VNI) map[common.VMAC]*net.UDPAddr {
	t.mu.RLock()
	defer t.mu.RUnlock()
	src := t.remoteByVNI[vni]
	if len(src) == 0 {
		return nil
	}
	out := make(map[common.VMAC]*net.UDPAddr, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// AgeOutRemotes drops remote entries with lastSeen older than maxAge.
// Returns the number of entries removed. Call periodically from a reaper.
func (t *MACTable) AgeOutRemotes(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge)
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for k, e := range t.remote {
		if e.lastSeen.Before(cutoff) {
			delete(t.remote, k)
			if m := t.remoteByVNI[k.vni]; m != nil {
				delete(m, k.mac)
				if len(m) == 0 {
					delete(t.remoteByVNI, k.vni)
				}
			}
			n++
		}
	}
	return n
}

// CountLocal / CountRemote return current entry counts.
func (t *MACTable) CountLocal() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.local)
}

func (t *MACTable) CountRemote() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.remote)
}
