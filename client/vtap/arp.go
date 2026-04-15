package tap

import (
	"net/netip"
	"sync"

	"github.com/jabberwocky238/gasoline/common"
)

// ARPTable is the userspace IP→VMAC cache.
//
// Resolution flow no longer uses blocking WaitFor; instead the TAP device
// stages outbound IP packets in stagedIPPackets and drains them via
// OnLearn when the MAC is learned.
type ARPTable struct {
	mu      sync.RWMutex
	table   map[netip.Addr]common.VMAC
	onLearn func(netip.Addr, common.VMAC) // optional, fired by Set
}

func NewARPTable() *ARPTable {
	return &ARPTable{table: make(map[netip.Addr]common.VMAC)}
}

// SetLearnHook installs a callback fired (off-lock) on every successful Set.
// Used by the TAP device to drain its staging queue when an ARP reply
// arrives for a previously-unknown IP.
func (a *ARPTable) SetLearnHook(fn func(netip.Addr, common.VMAC)) {
	a.mu.Lock()
	a.onLearn = fn
	a.mu.Unlock()
}

// Set inserts/replaces an entry and fires the learn hook.
func (a *ARPTable) Set(ip netip.Addr, mac common.VMAC) {
	a.mu.Lock()
	a.table[ip] = mac
	hook := a.onLearn
	a.mu.Unlock()
	if hook != nil {
		hook(ip, mac)
	}
}

func (a *ARPTable) Delete(ip netip.Addr) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.table, ip)
}

// Lookup returns the cached MAC, or ok=false on miss.
func (a *ARPTable) Lookup(ip netip.Addr) (common.VMAC, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	v, ok := a.table[ip]
	return v, ok
}

func (a *ARPTable) Snapshot() map[netip.Addr]common.VMAC {
	a.mu.RLock()
	defer a.mu.RUnlock()
	cp := make(map[netip.Addr]common.VMAC, len(a.table))
	for k, v := range a.table {
		cp[k] = v
	}
	return cp
}

func (a *ARPTable) Len() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.table)
}
