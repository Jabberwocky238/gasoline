package vxlan

import (
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/jabberwocky238/gasoline/common"
)

type vmacKey struct {
	vni common.VNI
	mac common.VMAC
}

type localEntry struct {
	port  Port
	added time.Time
}

// remoteEntry's expires is atomic so the LearnRemote fast path can refresh
// the deadline under MutexGuard.Read without upgrading to Write.
type remoteEntry struct {
	addr    netip.AddrPort
	expires atomic.Int64 // absolute UnixNano deadline
}

const (
	defaultIdleTime      = 5 * time.Minute
	defaultRefreshWindow = 1 * time.Minute
)

// macTableState holds every map MACTable touches. All access is funnelled
// through the MutexGuard wrapping it. Maps are reference types so the
// value-copy passed to Read still aliases the same underlying storage.
type macTableState struct {
	local       map[vmacKey]*localEntry
	remote      map[vmacKey]*remoteEntry
	localByVNI  map[common.VNI]map[common.VMAC]Port
	remoteByVNI map[common.VNI]map[common.VMAC]netip.AddrPort
}

type MACTable struct {
	state *common.MutexGuard[macTableState]

	idleTime      time.Duration
	refreshWindow time.Duration
}

func NewMACTable() *MACTable {
	return &MACTable{
		state: common.WithGuard(macTableState{
			local:       make(map[vmacKey]*localEntry),
			remote:      make(map[vmacKey]*remoteEntry),
			localByVNI:  make(map[common.VNI]map[common.VMAC]Port),
			remoteByVNI: make(map[common.VNI]map[common.VMAC]netip.AddrPort),
		}),
		idleTime:      defaultIdleTime,
		refreshWindow: defaultRefreshWindow,
	}
}

func (t *MACTable) RegisterLocal(vni common.VNI, mac common.VMAC, port Port) {
	k := vmacKey{vni, mac}
	t.state.Write(func(s *macTableState) {
		s.local[k] = &localEntry{port: port, added: time.Now()}
		if _, ok := s.localByVNI[vni]; !ok {
			s.localByVNI[vni] = make(map[common.VMAC]Port)
		}
		s.localByVNI[vni][mac] = port

		if _, ok := s.remote[k]; ok {
			delete(s.remote, k)
			if m := s.remoteByVNI[vni]; m != nil {
				delete(m, mac)
			}
		}
	})
}

func (t *MACTable) UnregisterLocal(vni common.VNI, mac common.VMAC) {
	k := vmacKey{vni, mac}
	t.state.Write(func(s *macTableState) {
		delete(s.local, k)
		if m := s.localByVNI[vni]; m != nil {
			delete(m, mac)
			if len(m) == 0 {
				delete(s.localByVNI, vni)
			}
		}
	})
}

// LearnRemote: OVS-style RLock fast path → WLock slow path.
func (t *MACTable) LearnRemote(vni common.VNI, mac common.VMAC, addr netip.AddrPort) {
	k := vmacKey{vni, mac}
	nowNS := time.Now().UnixNano()
	refreshAt := nowNS + int64(t.refreshWindow)

	need := false
	t.state.Read(func(s macTableState) {
		if _, isLocal := s.local[k]; isLocal {
			return
		}
		if e, ok := s.remote[k]; ok && e.addr == addr {
			if e.expires.Load() > refreshAt {
				return // entry valid + not near expiry
			}
		}
		need = true
	})
	if !need {
		return
	}

	expires := nowNS + int64(t.idleTime)
	t.state.Write(func(s *macTableState) {
		if _, isLocal := s.local[k]; isLocal {
			return
		}
		if e, ok := s.remote[k]; ok && e.addr == addr {
			e.expires.Store(expires)
			return
		}
		ne := &remoteEntry{addr: addr}
		ne.expires.Store(expires)
		s.remote[k] = ne
		if _, ok := s.remoteByVNI[vni]; !ok {
			s.remoteByVNI[vni] = make(map[common.VMAC]netip.AddrPort)
		}
		s.remoteByVNI[vni][mac] = addr
	})
}

func (t *MACTable) ForgetRemote(vni common.VNI, mac common.VMAC) {
	k := vmacKey{vni, mac}
	t.state.Write(func(s *macTableState) {
		delete(s.remote, k)
		if m := s.remoteByVNI[vni]; m != nil {
			delete(m, mac)
			if len(m) == 0 {
				delete(s.remoteByVNI, vni)
			}
		}
	})
}

func (t *MACTable) LookupLocal(vni common.VNI, mac common.VMAC) (Port, bool) {
	var (
		port Port
		ok   bool
	)
	t.state.Read(func(s macTableState) {
		if e, found := s.local[vmacKey{vni, mac}]; found {
			port, ok = e.port, true
		}
	})
	return port, ok
}

func (t *MACTable) LookupRemote(vni common.VNI, mac common.VMAC) (netip.AddrPort, bool) {
	var (
		addr netip.AddrPort
		ok   bool
	)
	t.state.Read(func(s macTableState) {
		if e, found := s.remote[vmacKey{vni, mac}]; found {
			addr, ok = e.addr, true
		}
	})
	return addr, ok
}

// Lookup returns the first matching destination kind for (VNI, MAC):
//   - (port, zero, true)  → local
//   - (nil,  addr, true)  → remote
//   - (nil,  zero, false) → unknown
func (t *MACTable) Lookup(vni common.VNI, mac common.VMAC) (Port, netip.AddrPort, bool) {
	var (
		port Port
		addr netip.AddrPort
		ok   bool
	)
	t.state.Read(func(s macTableState) {
		k := vmacKey{vni, mac}
		if e, found := s.local[k]; found {
			port, ok = e.port, true
			return
		}
		if e, found := s.remote[k]; found {
			addr, ok = e.addr, true
		}
	})
	return port, addr, ok
}

func (t *MACTable) LocalsInVNI(vni common.VNI) map[common.VMAC]Port {
	var out map[common.VMAC]Port
	t.state.Read(func(s macTableState) {
		src := s.localByVNI[vni]
		if len(src) == 0 {
			return
		}
		out = make(map[common.VMAC]Port, len(src))
		for k, v := range src {
			out[k] = v
		}
	})
	return out
}

func (t *MACTable) RemotesInVNI(vni common.VNI) map[common.VMAC]netip.AddrPort {
	var out map[common.VMAC]netip.AddrPort
	t.state.Read(func(s macTableState) {
		src := s.remoteByVNI[vni]
		if len(src) == 0 {
			return
		}
		out = make(map[common.VMAC]netip.AddrPort, len(src))
		for k, v := range src {
			out[k] = v
		}
	})
	return out
}

// AgeOutRemotes drops remote entries whose effective last-refresh time
// (= expires - idleTime) is older than now-maxAge. maxAge=0 ages out all.
func (t *MACTable) AgeOutRemotes(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge).UnixNano()
	n := 0
	t.state.Write(func(s *macTableState) {
		for k, e := range s.remote {
			lastRefresh := e.expires.Load() - int64(t.idleTime)
			if lastRefresh <= cutoff {
				delete(s.remote, k)
				if m := s.remoteByVNI[k.vni]; m != nil {
					delete(m, k.mac)
					if len(m) == 0 {
						delete(s.remoteByVNI, k.vni)
					}
				}
				n++
			}
		}
	})
	return n
}

func (t *MACTable) CountLocal() int {
	var n int
	t.state.Read(func(s macTableState) { n = len(s.local) })
	return n
}

func (t *MACTable) CountRemote() int {
	var n int
	t.state.Read(func(s macTableState) { n = len(s.remote) })
	return n
}
