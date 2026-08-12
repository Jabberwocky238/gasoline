package consensus

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"

	"github.com/hashicorp/raft"
	"github.com/jabberwocky238/gasoline/protocol"
)

// vnetDef is the replicated definition of one virtual network (PRD §2.2). It
// carries the config Version (PRD §4.4): an upsert with a version not greater
// than the stored one is ignored, so a stale --root file can never overwrite a
// newer definition. version-greatest wins across the cluster.
type vnetDef struct {
	VNI      protocol.VNI_Ty
	Version  uint64
	Segments []Segment
	AuthKeys map[[32]byte]*keyGrant
}

type keyGrant struct {
	PubKey     [32]byte
	VNI        protocol.VNI_Ty
	AllowedSeg []netip.Prefix
	StaticIP   netip.Addr
}

// sessionEntry is the replicated per-session record (PRD §2.2). It includes the
// data-plane transport keys (PRD §7.2): they enter Raft so any PE a client hops
// to can decrypt its frames, which is what makes G4 multi-server hopping free.
type sessionEntry struct {
	SessionID    protocol.SessionID_Ty
	PubKey       [32]byte
	VNI          protocol.VNI_Ty
	IP           netip.Addr
	C2SKey       [32]byte // decrypts client->PE frames (client's Send key)
	S2CKey       [32]byte // encrypts PE->client frames (client's Recv key)
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
	case CmdSessionRekey:
		return m.applySessionRekey(cmd.SessionRekey)
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
	if ok && c.Version <= vn.Version {
		// A stale or equal-version upsert must not overwrite a newer definition
		// (PRD §4.4 — version-greatest wins). Silently ignore; this keeps the
		// operation idempotent so fsnotify re-firing the same file is a no-op.
		return nil
	}
	if !ok {
		vn = &vnetDef{VNI: c.VNI, AuthKeys: make(map[[32]byte]*keyGrant)}
		m.VNets[c.VNI] = vn
	}
	vn.Version = c.Version
	vn.Segments = c.Segments
	// The --root file is authoritative for this vnet's key table: replace it
	// wholesale so a key removed from the file is deauthorized on upsert.
	if c.AuthKeys != nil {
		next := make(map[[32]byte]*keyGrant, len(c.AuthKeys))
		for i := range c.AuthKeys {
			g := c.AuthKeys[i]
			next[g.PubKey] = &keyGrant{
				PubKey:     g.PubKey,
				VNI:        c.VNI,
				AllowedSeg: g.AllowedSeg,
				StaticIP:   g.StaticIP,
			}
		}
		vn.AuthKeys = next
	}
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

// ErrIPTaken is returned by an apply that would double-assign an IP. The assign
// server maps it to a retry (optimistic concurrency, PRD §2.3).
var ErrIPTaken = errors.New("consensus: ip already assigned")

func (m *meshState) applySessionCreate(c *SessionCreate) error {
	// IP-collision check: the pre-selected IP must be free (PRD §2.3).
	for _, s := range m.Sessions {
		if s.VNI == c.VNI && s.IP == c.IP {
			return ErrIPTaken
		}
	}
	e := &sessionEntry{
		SessionID:    c.SessionID,
		PubKey:       c.PubKey,
		VNI:          c.VNI,
		IP:           c.IP,
		C2SKey:       c.C2SKey,
		S2CKey:       c.S2CKey,
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

func (m *meshState) applySessionRekey(c *SessionRekey) error {
	e, ok := m.Sessions[c.SessionID]
	if !ok {
		return nil
	}
	e.C2SKey = c.C2SKey
	e.S2CKey = c.S2CKey
	e.LastSeenNano = c.Now
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

// SessionKeys is the data-plane view of a session the transport layer needs:
// the transport keys plus the full SessionID (so a 6-byte tag lookup can verify
// against the full id) and the current access point.
type SessionKeys struct {
	SessionID    protocol.SessionID_Ty
	VNI          protocol.VNI_Ty
	IP           netip.Addr
	C2SKey       [32]byte
	S2CKey       [32]byte
	LastOperator [16]byte
}

// SessionRoute is the routing view of a session: which overlay IP maps to which
// session on which operator. RouteSnapshot returns one per live session so an
// operator can rebuild its routing map from the replicated state (PRD §5.4.1 /
// §6.1 — routing is Raft-driven, not manually pushed).
type SessionRoute struct {
	SessionID    protocol.SessionID_Ty
	VNI          protocol.VNI_Ty
	IP           netip.Addr
	LastOperator [16]byte
}

// RouteSnapshotByVNI returns routing entries for the live sessions of a single
// VNI. An operator syncs its routing map per-VNI (only the vnets it hosts),
// never the whole mesh — so route sync cost scales with a node's own VNIs, not
// the global session count.
func (m *meshState) RouteSnapshotByVNI(vni protocol.VNI_Ty) []SessionRoute {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []SessionRoute
	for _, e := range m.Sessions {
		if e.VNI != vni {
			continue
		}
		out = append(out, SessionRoute{
			SessionID:    e.SessionID,
			VNI:          e.VNI,
			IP:           e.IP,
			LastOperator: e.LastOperator,
		})
	}
	return out
}

// SessionByTag resolves a session from its 6-byte SessionTag (PRD §6.4): the
// first 6 bytes of the SessionID. A tag collision (~10^-3 at 10^6 sessions)
// yields the wrong entry, whose keys then fail AEAD open — a dropped packet, not
// a security hole. Linear scan is fine for now; if session counts grow this
// gains a tag->id index alongside pubKeyToSession.
func (m *meshState) SessionByTag(tag [6]byte) (SessionKeys, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for sid, e := range m.Sessions {
		if [6]byte(sid[:6]) == tag {
			return SessionKeys{
				SessionID:    e.SessionID,
				VNI:          e.VNI,
				IP:           e.IP,
				C2SKey:       e.C2SKey,
				S2CKey:       e.S2CKey,
				LastOperator: e.LastOperator,
			}, true
		}
	}
	return SessionKeys{}, false
}

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

// VNetVersion returns the stored config version for a vnet, and whether the
// vnet exists. fsnotify uses it to decide whether a --root file is newer than
// what Raft holds (PRD §4.4).
func (m *meshState) VNetVersion(vni protocol.VNI_Ty) (uint64, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	vn, ok := m.VNets[vni]
	if !ok {
		return 0, false
	}
	return vn.Version, true
}

// PickIP resolves an address for pubkey on vni against the current local
// replica. Priority (PRD §4.2):
//
//  1. A pinned StaticIP on the key grant (fixed IP) — returned as-is.
//  2. Otherwise the first free address in any allowed segment's pool,
//     skipping reserved addresses and any IP already assigned in the vni.
//
// This is optimistic: the caller proposes SessionCreate with the returned IP,
// and the FSM rejects on a commit-time collision so the caller retries. ranges
// is the segment CIDR the IP was drawn from. ok is false when the key is not
// granted or the pool is exhausted.
func (m *meshState) PickIP(vni protocol.VNI_Ty, pub [32]byte) (ip netip.Addr, ranges netip.Prefix, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	vn, exists := m.VNets[vni]
	if !exists {
		return netip.Addr{}, netip.Prefix{}, false
	}
	grant, granted := vn.AuthKeys[pub]
	if !granted {
		return netip.Addr{}, netip.Prefix{}, false
	}

	// 1. Pinned fixed IP.
	if grant.StaticIP.IsValid() {
		return grant.StaticIP, segmentOf(vn, grant.StaticIP), true
	}

	// 2. First free pool address in an allowed segment.
	used := m.usedIPsLocked(vni)
	for _, seg := range vn.Segments {
		if !allowedSegment(grant, seg.CIDR) {
			continue
		}
		reserved := make(map[netip.Addr]struct{}, len(seg.Reserved))
		for _, r := range seg.Reserved {
			reserved[r] = struct{}{}
		}
		for a := seg.Pool.Masked().Addr(); seg.Pool.Contains(a); a = a.Next() {
			if _, r := reserved[a]; r {
				continue
			}
			if _, u := used[a]; u {
				continue
			}
			return a, seg.CIDR, true
		}
	}
	return netip.Addr{}, netip.Prefix{}, false
}

// usedIPsLocked returns the set of IPs currently assigned in vni. Caller holds
// the read lock.
func (m *meshState) usedIPsLocked(vni protocol.VNI_Ty) map[netip.Addr]struct{} {
	used := make(map[netip.Addr]struct{})
	for _, s := range m.Sessions {
		if s.VNI == vni {
			used[s.IP] = struct{}{}
		}
	}
	return used
}

// allowedSegment reports whether a grant may draw from segment cidr. An empty
// AllowedSeg means "any segment in the vni".
func allowedSegment(g *keyGrant, cidr netip.Prefix) bool {
	if len(g.AllowedSeg) == 0 {
		return true
	}
	for _, s := range g.AllowedSeg {
		if s == cidr {
			return true
		}
	}
	return false
}

// segmentOf returns the segment CIDR containing ip, or the zero prefix.
func segmentOf(vn *vnetDef, ip netip.Addr) netip.Prefix {
	for _, seg := range vn.Segments {
		if seg.CIDR.Contains(ip) {
			return seg.CIDR
		}
	}
	return netip.Prefix{}
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
