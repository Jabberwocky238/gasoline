package vxlan

import (
	"net/netip"
	"sync"
	"sync/atomic"
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
//
// `expires` is the absolute Unix-nanos deadline after which the entry is
// considered stale (AgeOutRemotes reaps it). It is stored as atomic.Int64 so
// the "refresh" path can bump it under an RLock without upgrading to WLock.
//
// Follows OVS mac-learning.c: insert-time sets expires = now + idleTime, and
// per-packet re-learning touches expires only when the entry is within a
// refresh window of its deadline — most packets cause zero writes.
type remoteEntry struct {
	addr    netip.AddrPort
	expires atomic.Int64 // absolute expiry (UnixNano); 0 only mid-init
}

// Tunables for the OVS-style fast-path refresh policy.
//
//	idleTime        : how long before a quiet entry is aged out.
//	refreshWindow   : when the remaining lifetime drops below this, the next
//	                  packet upgrades to WLock and bumps expires. Making this
//	                  large relative to per-packet arrival rate bounds write
//	                  frequency to ~ 1 / (idleTime - refreshWindow) per entry.
const (
	defaultIdleTime      = 5 * time.Minute
	defaultRefreshWindow = 1 * time.Minute
)

// MACTable is the VXLAN plane's L2 forwarding database.
//
// It maintains two side-by-side indexes:
//
//	local  : (VNI, MAC) → Port            // locally-attached destinations
//	remote : (VNI, MAC) → netip.AddrPort  // learned via inbound VXLAN frames
//
// A second pair of indexes (byVNI) supports flood operations efficiently.
//
// All methods are O(1) on the hot path and safe for concurrent use. LearnRemote
// follows the OVS pattern: a common-case RLock fast path returns without any
// writes when the (mac, addr) binding already exists and isn't near expiry.
type MACTable struct {
	mu sync.RWMutex

	local  map[vmacKey]*localEntry
	remote map[vmacKey]*remoteEntry

	// Per-VNI sets used by Flood — kept in sync with local/remote.
	localByVNI  map[common.VNI]map[common.VMAC]Port
	remoteByVNI map[common.VNI]map[common.VMAC]netip.AddrPort

	idleTime      time.Duration
	refreshWindow time.Duration
}

func NewMACTable() *MACTable {
	return &MACTable{
		local:         make(map[vmacKey]*localEntry),
		remote:        make(map[vmacKey]*remoteEntry),
		localByVNI:    make(map[common.VNI]map[common.VMAC]Port),
		remoteByVNI:   make(map[common.VNI]map[common.VMAC]netip.AddrPort),
		idleTime:      defaultIdleTime,
		refreshWindow: defaultRefreshWindow,
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
//
// Structured after OVS mac_learning_update (lib/mac-learning.c:567):
//
//   - Fast path under RLock asks "does anything actually need writing?".
//     In steady state (same addr, not near expiry) this returns without
//     taking a lock upgrade, without allocating, and without touching any
//     cache line.
//   - Slow path takes the WLock, re-checks (state may have shifted while the
//     RLock was released), then inserts / bumps expires / migrates addr.
func (t *MACTable) LearnRemote(vni common.VNI, mac common.VMAC, addr netip.AddrPort) {
	k := vmacKey{vni, mac}
	nowNS := time.Now().UnixNano()
	refreshAt := nowNS + int64(t.refreshWindow)

	// Fast path: common case — entry already exists with this addr and is
	// still comfortably within its lifetime. No writes at all.
	t.mu.RLock()
	if _, isLocal := t.local[k]; isLocal {
		t.mu.RUnlock()
		return
	}
	need := true
	if e, ok := t.remote[k]; ok && e.addr == addr {
		// Entry matches. Only enter slow path when we're inside the refresh
		// window of the deadline — i.e. expires - now < refreshWindow.
		if e.expires.Load() > refreshAt {
			need = false
		}
	}
	t.mu.RUnlock()
	if !need {
		return
	}

	// Slow path: something needs writing — take WLock and re-check.
	expires := nowNS + int64(t.idleTime)
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, isLocal := t.local[k]; isLocal {
		return
	}
	if e, ok := t.remote[k]; ok && e.addr == addr {
		// Still same addr — just bump the deadline.
		e.expires.Store(expires)
		return
	}
	// New entry or addr migrated.
	ne := &remoteEntry{addr: addr}
	ne.expires.Store(expires)
	t.remote[k] = ne
	if _, ok := t.remoteByVNI[vni]; !ok {
		t.remoteByVNI[vni] = make(map[common.VMAC]netip.AddrPort)
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

// LookupRemote returns the learned UDP endpoint for (VNI, MAC) or
// (zero, false).
func (t *MACTable) LookupRemote(vni common.VNI, mac common.VMAC) (netip.AddrPort, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.remote[vmacKey{vni, mac}]
	if !ok {
		return netip.AddrPort{}, false
	}
	return e.addr, true
}

// Lookup returns the first matching destination kind for (VNI, MAC):
//   - (port, zero, true)  → local
//   - (nil,  addr, true)  → remote
//   - (nil,  zero, false) → unknown
func (t *MACTable) Lookup(vni common.VNI, mac common.VMAC) (Port, netip.AddrPort, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if e, ok := t.local[vmacKey{vni, mac}]; ok {
		return e.port, netip.AddrPort{}, true
	}
	if e, ok := t.remote[vmacKey{vni, mac}]; ok {
		return nil, e.addr, true
	}
	return nil, netip.AddrPort{}, false
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
func (t *MACTable) RemotesInVNI(vni common.VNI) map[common.VMAC]netip.AddrPort {
	t.mu.RLock()
	defer t.mu.RUnlock()
	src := t.remoteByVNI[vni]
	if len(src) == 0 {
		return nil
	}
	out := make(map[common.VMAC]netip.AddrPort, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// AgeOutRemotes drops remote entries whose expires deadline is older than
// (now - maxAge). Passing maxAge=0 matches the historical behaviour of
// "treat everything as stale". Returns the number of entries removed.
func (t *MACTable) AgeOutRemotes(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge).UnixNano()
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for k, e := range t.remote {
		// The effective "last refreshed at" time is expires - idleTime.
		lastRefresh := e.expires.Load() - int64(t.idleTime)
		if lastRefresh <= cutoff {
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
