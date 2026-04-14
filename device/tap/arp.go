package tap

import (
	"net/netip"
	"sync"
	"time"

	"github.com/jabberwocky238/gasoline/common"
)

// ARPTable is the TAP device's userspace IP→VMAC cache.
//
//   - Lookup(): cached MAC, ok=false on miss.
//   - WaitFor(): blocking resolution channel with timeout fallback.
//   - Set():    populates an entry and wakes pending waiters.
//
// The OS kernel ARP layer is bypassed entirely — the whole L2 fabric runs
// in userspace.
type ARPTable struct {
	mu      sync.Mutex
	table   map[netip.Addr]common.VMAC
	pending map[netip.Addr][]chan common.VMAC
}

func NewARPTable() *ARPTable {
	return &ARPTable{
		table:   make(map[netip.Addr]common.VMAC),
		pending: make(map[netip.Addr][]chan common.VMAC),
	}
}

func (a *ARPTable) Set(ip netip.Addr, mac common.VMAC) {
	a.mu.Lock()
	a.table[ip] = mac
	waiters := a.pending[ip]
	delete(a.pending, ip)
	a.mu.Unlock()
	for _, ch := range waiters {
		select {
		case ch <- mac:
		default:
		}
	}
}

func (a *ARPTable) Delete(ip netip.Addr) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.table, ip)
}

func (a *ARPTable) Lookup(ip netip.Addr) (common.VMAC, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	v, ok := a.table[ip]
	return v, ok
}

// WaitFor blocks until ip is resolved or timeout fires (timeout delivers
// a zero VMAC value to signal "give up").
func (a *ARPTable) WaitFor(ip netip.Addr, timeout time.Duration) <-chan common.VMAC {
	a.mu.Lock()
	if v, ok := a.table[ip]; ok {
		a.mu.Unlock()
		ch := make(chan common.VMAC, 1)
		ch <- v
		return ch
	}
	ch := make(chan common.VMAC, 1)
	a.pending[ip] = append(a.pending[ip], ch)
	a.mu.Unlock()

	go func() {
		<-time.After(timeout)
		a.mu.Lock()
		for i, c := range a.pending[ip] {
			if c == ch {
				a.pending[ip] = append(a.pending[ip][:i], a.pending[ip][i+1:]...)
				if len(a.pending[ip]) == 0 {
					delete(a.pending, ip)
				}
				break
			}
		}
		a.mu.Unlock()
		select {
		case ch <- common.VMAC{}:
		default:
		}
	}()
	return ch
}

func (a *ARPTable) Snapshot() map[netip.Addr]common.VMAC {
	a.mu.Lock()
	defer a.mu.Unlock()
	cp := make(map[netip.Addr]common.VMAC, len(a.table))
	for k, v := range a.table {
		cp[k] = v
	}
	return cp
}

func (a *ARPTable) Len() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.table)
}
