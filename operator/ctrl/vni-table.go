package ctrl

import (
	"github.com/jabberwocky238/gasoline/common"
)

// vnetSessionsState is the guarded inner state of VNetSessions.
//
//	Sessions : sessionID  → *SessionInfo  (authoritative)
//	byVMAC   : common.VMAC → sessionID    (secondary, data-plane lookup)
type vnetSessionsState struct {
	Sessions map[[16]byte]*SessionInfo
	byVMAC   map[common.VMAC][16]byte
}

// VNetSessions holds all sessions belonging to a single VNI. Concurrency is
// managed by a common.MutexGuard over the inner state so readers and writers
// go through a single critical section each.
type VNetSessions struct {
	guard *common.MutexGuard[vnetSessionsState]
}

func newVNetSessions() *VNetSessions {
	return &VNetSessions{
		guard: common.WithGuard(vnetSessionsState{
			Sessions: make(map[[16]byte]*SessionInfo),
			byVMAC:   make(map[common.VMAC][16]byte),
		}),
	}
}

// Add inserts/replaces a session and keeps byVMAC in sync. If sessionID
// already exists with a different VMAC the stale byVMAC entry is cleaned up.
func (v *VNetSessions) Add(sessionID [16]byte, info *SessionInfo) {
	v.guard.Write(func(s *vnetSessionsState) {
		if old, ok := s.Sessions[sessionID]; ok {
			if cur, hit := s.byVMAC[old.VMAC]; hit && cur == sessionID {
				delete(s.byVMAC, old.VMAC)
			}
		}
		s.Sessions[sessionID] = info
		var zero common.VMAC
		if info.VMAC != zero {
			s.byVMAC[info.VMAC] = sessionID
		}
	})
}

// Remove deletes a session and its byVMAC entry.
func (v *VNetSessions) Remove(sessionID [16]byte) {
	v.guard.Write(func(s *vnetSessionsState) {
		info, ok := s.Sessions[sessionID]
		if !ok {
			return
		}
		delete(s.Sessions, sessionID)
		if cur, hit := s.byVMAC[info.VMAC]; hit && cur == sessionID {
			delete(s.byVMAC, info.VMAC)
		}
	})
}

// Get returns the SessionInfo for a sessionID.
func (v *VNetSessions) Get(sessionID [16]byte) (info *SessionInfo, found bool) {
	v.guard.Read(func(s vnetSessionsState) {
		info, found = s.Sessions[sessionID]
	})
	return
}

// LookupByVMAC finds a session by its VMAC in O(1). Primary data-plane
// lookup — no packet inspection involved.
func (v *VNetSessions) LookupByVMAC(cid common.VMAC) (sessionID [16]byte, info *SessionInfo, found bool) {
	v.guard.Read(func(s vnetSessionsState) {
		sid, ok := s.byVMAC[cid]
		if !ok {
			return
		}
		sessionID = sid
		info = s.Sessions[sid]
		found = true
	})
	return
}

// Snapshot returns a shallow copy of the sessionID → SessionInfo map.
func (v *VNetSessions) Snapshot() map[[16]byte]*SessionInfo {
	var out map[[16]byte]*SessionInfo
	v.guard.Read(func(s vnetSessionsState) {
		out = make(map[[16]byte]*SessionInfo, len(s.Sessions))
		for k, inf := range s.Sessions {
			out[k] = inf
		}
	})
	return out
}
