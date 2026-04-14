package ctrl

import (
	"net/netip"
	"sync"

	"github.com/jabberwocky238/gasoline/common"
)

// VNetSessions holds all sessions belonging to a single VNI with three
// secondary indexes so every data-plane lookup is O(1):
//
//	Sessions   : sessionID     → *SessionInfo  (authoritative)
//	byIP       : netip.Addr    → sessionID
//	byVMAC : common.VMAC → sessionID
//
// All three maps are kept in sync under a single RWMutex.
type VNetSessions struct {
	mu         sync.RWMutex
	Sessions   map[[16]byte]*SessionInfo
	byIP       map[netip.Addr][16]byte
	byVMAC map[common.VMAC][16]byte
}

func newVNetSessions() *VNetSessions {
	return &VNetSessions{
		Sessions:   make(map[[16]byte]*SessionInfo),
		byIP:       make(map[netip.Addr][16]byte),
		byVMAC: make(map[common.VMAC][16]byte),
	}
}

// Add inserts/replaces a session and its secondary index entries.
// If the sessionID already exists with different IP/ClientID the stale
// index entries are cleaned up first.
func (v *VNetSessions) Add(sessionID [16]byte, info *SessionInfo) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Remove stale secondary index entries if this sessionID is being replaced.
	if old, ok := v.Sessions[sessionID]; ok {
		if old.IP.IsValid() {
			if cur, hit := v.byIP[old.IP]; hit && cur == sessionID {
				delete(v.byIP, old.IP)
			}
		}
		if cur, hit := v.byVMAC[old.VMAC]; hit && cur == sessionID {
			delete(v.byVMAC, old.VMAC)
		}
	}

	v.Sessions[sessionID] = info
	if info.IP.IsValid() {
		v.byIP[info.IP] = sessionID
	}
	var zero common.VMAC
	if info.VMAC != zero {
		v.byVMAC[info.VMAC] = sessionID
	}
}

// Remove deletes a session and its secondary index entries.
func (v *VNetSessions) Remove(sessionID [16]byte) {
	v.mu.Lock()
	defer v.mu.Unlock()

	info, ok := v.Sessions[sessionID]
	if !ok {
		return
	}
	delete(v.Sessions, sessionID)
	if info.IP.IsValid() {
		if cur, hit := v.byIP[info.IP]; hit && cur == sessionID {
			delete(v.byIP, info.IP)
		}
	}
	if cur, hit := v.byVMAC[info.VMAC]; hit && cur == sessionID {
		delete(v.byVMAC, info.VMAC)
	}
}

// Get returns the SessionInfo for a sessionID.
func (v *VNetSessions) Get(sessionID [16]byte) (*SessionInfo, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	s, ok := v.Sessions[sessionID]
	return s, ok
}

// LookupByIP finds a session by its assigned IP in O(1).
func (v *VNetSessions) LookupByIP(ip netip.Addr) (sessionID [16]byte, info *SessionInfo, found bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	sid, ok := v.byIP[ip]
	if !ok {
		return [16]byte{}, nil, false
	}
	return sid, v.Sessions[sid], true
}

// LookupByVMAC finds a session by its ClientID in O(1).
// Primary data-plane lookup — no packet inspection involved.
func (v *VNetSessions) LookupByVMAC(cid common.VMAC) (sessionID [16]byte, info *SessionInfo, found bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	sid, ok := v.byVMAC[cid]
	if !ok {
		return [16]byte{}, nil, false
	}
	return sid, v.Sessions[sid], true
}
