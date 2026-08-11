package consensus

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"net/netip"
	"sync"

	"github.com/hashicorp/raft"
	"github.com/jabberwocky238/gasoline/protocol"
)

// vnetDef is the replicated definition of one virtual network (PRD §2.2).
type vnetDef struct {
	VNI      protocol.VNI_Ty
	Segments []Segment
	AuthKeys map[[32]byte]*keyGrant
}

type keyGrant struct {
	PubKey     [32]byte
	VNI        protocol.VNI_Ty
	AllowedSeg []netip.Prefix
	StaticIP   netip.Addr
}

// sessionEntry is the replicated per-session record (PRD §2.2). The data-plane
// transport keys are deliberately NOT here — they never enter Raft.
type sessionEntry struct {
	SessionID    protocol.SessionID_Ty
	PubKey       [32]byte
	VNI          protocol.VNI_Ty
	IP           netip.Addr
	HopSecret    [32]byte
	LastOperator [16]byte
	LastSeenNano int64
	ExpiresNano  int64
}

// meshState is the Raft state machine. Every operator holds a full replica.
// It is the single source of truth for vnets, key grants and sessions.
type meshState struct {
	mu       sync.RWMutex
	VNets    map[protocol.VNI_Ty]*vnetDef
	Sessions map[protocol.SessionID_Ty]*sessionEntry

	// pubKeyToSession is the reverse index for the uniqueness check
	// (PRD §8.0.4): O(1) "does this key already have a live session?".
	pubKeyToSession map[[32]byte]protocol.SessionID_Ty
}

// NewMeshState returns an empty FSM.
func NewMeshState() *meshState {
	return &meshState{
		VNets:           make(map[protocol.VNI_Ty]*vnetDef),
		Sessions:        make(map[protocol.SessionID_Ty]*sessionEntry),
		pubKeyToSession: make(map[[32]byte]protocol.SessionID_Ty),
	}
}

// --------------- raft.FSM ---------------

// ApplyResult is returned through raft.ApplyFuture.Response(). A nil Err
// means success; callers (e.g. handshake) inspect it to know whether the
// IP pre-selection collided.
type ApplyResult struct {
	Err error
}

// Apply runs one committed log entry against the state. It must be
// deterministic: identical logs produce identical state on every node,
// so it never reads wall-clock time — proposers stamp Now into commands.
func (m *meshState) Apply(l *raft.Log) interface{} {
	cmd, err := DecodeCommand(l.Data)
	if err != nil {
		return ApplyResult{Err: err}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return ApplyResult{Err: m.applyLocked(cmd)}
}

func (m *meshState) applyLocked(cmd *Command) error {
	switch cmd.Kind {
	case CmdBatch:
		for i := range cmd.Batch {
			if err := m.applyLocked(&cmd.Batch[i]); err != nil {
				// A bad sub-command must not abort the rest: the batch is a
				// transport optimization, not a transaction.
				continue
			}
		}
		return nil
	case CmdVNetUpsert:
		return m.applyVNetUpsert(cmd.VNetUpsert)
	case CmdKeyGrant:
		return m.applyKeyGrant(cmd.KeyGrant)
	case CmdKeyRevoke:
		return m.applyKeyRevoke(cmd.KeyRevoke)
	case CmdSessionCreate:
		return m.applySessionCreate(cmd.SessionCreate)
	case CmdSessionRenew:
		return m.applySessionRenew(cmd.SessionRenew)
	case CmdSessionMigrate:
		return m.applySessionMigrate(cmd.SessionMigrate)
	case CmdSessionDrop:
		return m.applySessionDrop(cmd.SessionDrop)
	case CmdSessionReplace:
		return m.applySessionReplace(cmd.SessionReplace)
	default:
		return fmt.Errorf("consensus: unknown command kind %#x", byte(cmd.Kind))
	}
}

func (m *meshState) applyVNetUpsert(c *VNetUpsert) error {
	// Enforce Pool ⊆ CIDR (PRD §2.2 hard constraint).
	for _, seg := range c.Segments {
		if !prefixContainsPrefix(seg.CIDR, seg.Pool) {
			return fmt.Errorf("consensus: vnet %s: pool %s not within cidr %s",
				c.VNI, seg.Pool, seg.CIDR)
		}
	}
	vn, ok := m.VNets[c.VNI]
	if !ok {
		vn = &vnetDef{VNI: c.VNI, AuthKeys: make(map[[32]byte]*keyGrant)}
		m.VNets[c.VNI] = vn
	}
	vn.Segments = c.Segments
	return nil
}

func (m *meshState) applyKeyGrant(c *KeyGrant) error {
	vn, ok := m.VNets[c.VNI]
	if !ok {
		return fmt.Errorf("consensus: key grant for unknown vni %s", c.VNI)
	}
	vn.AuthKeys[c.PubKey] = &keyGrant{
		PubKey:     c.PubKey,
		VNI:        c.VNI,
		AllowedSeg: c.AllowedSeg,
		StaticIP:   c.StaticIP,
	}
	return nil
}

func (m *meshState) applyKeyRevoke(c *KeyRevoke) error {
	vn, ok := m.VNets[c.VNI]
	if !ok {
		return nil
	}
	delete(vn.AuthKeys, c.PubKey)
	// Cascade: drop any live session for this key.
	if sid, ok := m.pubKeyToSession[c.PubKey]; ok {
		m.removeSessionLocked(sid)
	}
	return nil
}

func (m *meshState) applySessionCreate(c *SessionCreate) error {
	// IP-collision check: the pre-selected IP must be free (PRD §2.3).
	for _, s := range m.Sessions {
		if s.VNI == c.VNI && s.IP == c.IP {
			return fmt.Errorf("consensus: ip %s already assigned in vni %s", c.IP, c.VNI)
		}
	}
	e := &sessionEntry{
		SessionID:    c.SessionID,
		PubKey:       c.PubKey,
		VNI:          c.VNI,
		IP:           c.IP,
		HopSecret:    c.HopSecret,
		LastOperator: c.Operator,
		LastSeenNano: c.Now,
		ExpiresNano:  c.Now + int64(c.LeaseTTL),
	}
	m.Sessions[c.SessionID] = e
	m.pubKeyToSession[c.PubKey] = c.SessionID
	return nil
}

func (m *meshState) applySessionRenew(c *SessionRenew) error {
	e, ok := m.Sessions[c.SessionID]
	if !ok {
		return nil
	}
	e.LastSeenNano = c.Now
	e.ExpiresNano = c.Now + int64(c.LeaseTTL)
	return nil
}

func (m *meshState) applySessionMigrate(c *SessionMigrate) error {
	e, ok := m.Sessions[c.SessionID]
	if !ok {
		return nil
	}
	e.LastOperator = c.Operator
	e.LastSeenNano = c.Now
	return nil
}

func (m *meshState) applySessionDrop(c *SessionDrop) error {
	m.removeSessionLocked(c.SessionID)
	return nil
}

func (m *meshState) applySessionReplace(c *SessionReplace) error {
	// Atomic: remove any existing session for this pubkey, then create.
	if sid, ok := m.pubKeyToSession[c.New.PubKey]; ok {
		m.removeSessionLocked(sid)
	}
	return m.applySessionCreate(&c.New)
}

// removeSessionLocked deletes a session and its reverse-index entry.
func (m *meshState) removeSessionLocked(sid protocol.SessionID_Ty) {
	e, ok := m.Sessions[sid]
	if !ok {
		return
	}
	delete(m.Sessions, sid)
	if cur, ok := m.pubKeyToSession[e.PubKey]; ok && cur == sid {
		delete(m.pubKeyToSession, e.PubKey)
	}
}

// --------------- snapshot / restore ---------------

// snapshotData is the gob-serializable projection of meshState.
type snapshotData struct {
	VNets    map[protocol.VNI_Ty]*vnetDef
	Sessions map[protocol.SessionID_Ty]*sessionEntry
}

// Snapshot captures the state for log compaction. Called with FSM otherwise
// quiescent by raft; we still copy under lock to be safe.
func (m *meshState) Snapshot() (raft.FSMSnapshot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	data := snapshotData{
		VNets:    make(map[protocol.VNI_Ty]*vnetDef, len(m.VNets)),
		Sessions: make(map[protocol.SessionID_Ty]*sessionEntry, len(m.Sessions)),
	}
	for k, v := range m.VNets {
		data.VNets[k] = v
	}
	for k, v := range m.Sessions {
		data.Sessions[k] = v
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(data); err != nil {
		return nil, err
	}
	return &fsmSnapshot{blob: buf.Bytes()}, nil
}

// Restore replaces the entire state from a snapshot stream.
func (m *meshState) Restore(rc io.ReadCloser) error {
	defer rc.Close()
	var data snapshotData
	if err := gob.NewDecoder(rc).Decode(&data); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.VNets = data.VNets
	if m.VNets == nil {
		m.VNets = make(map[protocol.VNI_Ty]*vnetDef)
	}
	m.Sessions = data.Sessions
	if m.Sessions == nil {
		m.Sessions = make(map[protocol.SessionID_Ty]*sessionEntry)
	}
	// Rebuild the reverse index; it is not persisted.
	m.pubKeyToSession = make(map[[32]byte]protocol.SessionID_Ty, len(m.Sessions))
	for sid, e := range m.Sessions {
		m.pubKeyToSession[e.PubKey] = sid
	}
	return nil
}

type fsmSnapshot struct{ blob []byte }

func (s *fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	if _, err := sink.Write(s.blob); err != nil {
		_ = sink.Cancel()
		return err
	}
	return sink.Close()
}

func (s *fsmSnapshot) Release() {}

// --------------- read-side accessors (local, no consensus) ---------------
//
// Reads hit the local replica directly; they never go through Raft. Callers
// tolerate slight staleness on followers (bounded by replication lag).

// SessionByID returns a copy of the session, if present.
func (m *meshState) SessionByID(sid protocol.SessionID_Ty) (sessionEntry, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.Sessions[sid]
	if !ok {
		return sessionEntry{}, false
	}
	return *e, true
}

// SessionByPubKey returns the live session for a pubkey, if any.
func (m *meshState) SessionByPubKey(pub [32]byte) (sessionEntry, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sid, ok := m.pubKeyToSession[pub]
	if !ok {
		return sessionEntry{}, false
	}
	e := m.Sessions[sid]
	return *e, true
}

// SessionCount reports the number of live sessions (test / observability).
func (m *meshState) SessionCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.Sessions)
}

// VNetCount reports the number of registered vnets (test / observability).
func (m *meshState) VNetCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.VNets)
}

// --------------- helpers ---------------

// prefixContainsPrefix reports whether outer fully contains inner.
func prefixContainsPrefix(outer, inner netip.Prefix) bool {
	if outer.Addr().Is4() != inner.Addr().Is4() {
		return false
	}
	if inner.Bits() < outer.Bits() {
		return false
	}
	return outer.Contains(inner.Masked().Addr())
}
