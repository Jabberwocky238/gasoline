package protocol

import (
	"context"
	"net/netip"
	"sync"
)

type VNI_Ty uint32
type CID_Ty [8]byte
type SessionID_Ty [16]byte

// SessionState holds all mutable session fields. It carries no lock; access
// is mediated by the enclosing SessionContext.
type SessionState struct {
	ipPrefix netip.Prefix   // Client's assigned IP (e.g. 10.0.0.2/24)
	ipRanges []netip.Prefix // Internal network ranges routable via VPN
}

type PreassignedSessionConfig struct {
	cid CID_Ty // 16 hex chars of the SessionID, used as the client's virtual MAC address
	vni VNI_Ty // 24-bit virtual network identifier
}

func NewPreassignedSessionConfig(cid CID_Ty, vni VNI_Ty) PreassignedSessionConfig {
	return PreassignedSessionConfig{cid: cid, vni: vni}
}

func (p PreassignedSessionConfig) CID() CID_Ty { return p.cid }
func (p PreassignedSessionConfig) VNI() VNI_Ty { return p.vni }

type SessionContext struct {
	mu  sync.RWMutex
	ctx context.Context
	// configured in session
	state SessionState
	// preassigned
	preassigned PreassignedSessionConfig
	// generated during handshake
	sessionID SessionID_Ty // Session ID assigned by server
}

func NewSessionContext(ctx context.Context, preassigned PreassignedSessionConfig) *SessionContext {
	return &SessionContext{
		ctx:         ctx,
		preassigned: preassigned,
	}
}

// Modify executes fn with the write lock held, allowing batched mutations.
// The passed state pointer is valid only for the duration of fn.
func (s *SessionContext) Modify(fn func(st *SessionState)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.state)
}

func (s *SessionContext) Context() context.Context {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ctx
}

func (s *SessionContext) CID() CID_Ty {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.preassigned.cid
}

func (s *SessionContext) VNI() VNI_Ty {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.preassigned.vni
}

func (s *SessionContext) SessionID() SessionID_Ty {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessionID
}

func (s *SessionContext) IPPrefix() netip.Prefix {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.ipPrefix
}

func (s *SessionContext) IPRanges() []netip.Prefix {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.ipRanges
}
