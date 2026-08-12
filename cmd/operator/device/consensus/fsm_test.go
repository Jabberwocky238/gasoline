package consensus

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jabberwocky238/gasoline/protocol"
)

// applyCmd runs a command straight through the FSM (no raft), returning the
// per-command error. Mirrors what the raft driver loop delivers.
func applyCmd(t *testing.T, m *meshState, cmd *Command) error {
	t.Helper()
	return m.ApplyCommand(cmd).Err
}

func sid(b byte) protocol.SessionID_Ty {
	var s protocol.SessionID_Ty
	s[0] = b
	return s
}

func pub(b byte) [32]byte {
	var p [32]byte
	p[0] = b
	return p
}

// seedVNet installs vnet 200 with a pool and grants the given pubkeys, so
// SessionCreate can allocate an address in Apply.
func seedVNet(t *testing.T, m *meshState, pubs ...byte) {
	t.Helper()
	if err := applyCmd(t, m, &Command{Kind: CmdVNetUpsert, VNetUpsert: &VNetUpsert{
		VNI: 200, Version: 1,
		Segments: []Segment{{
			CIDR: netip.MustParsePrefix("10.0.1.0/24"),
			Pool: netip.MustParsePrefix("10.0.1.16/28"),
		}},
	}}); err != nil {
		t.Fatalf("seed vnet: %v", err)
	}
	for _, b := range pubs {
		if err := applyCmd(t, m, &Command{Kind: CmdKeyGrant, KeyGrant: &KeyGrant{VNI: 200, PubKey: pub(b)}}); err != nil {
			t.Fatalf("grant key %d: %v", b, err)
		}
	}
}

// applyCreate runs a SessionCreate and returns the allocated IP + error.
func applyCreate(t *testing.T, m *meshState, c *SessionCreate) (netip.Addr, error) {
	t.Helper()
	ar := m.ApplyCommand(&Command{Kind: CmdSessionCreate, SessionCreate: c})
	return ar.IP, ar.Err
}

func TestVNetUpsertEnforcesPoolWithinCIDR(t *testing.T) {
	m := NewMeshState()

	// Pool outside CIDR must be rejected.
	err := applyCmd(t, m, &Command{Kind: CmdVNetUpsert, VNetUpsert: &VNetUpsert{
		VNI: 200,
		Segments: []Segment{{
			CIDR: netip.MustParsePrefix("10.0.1.0/24"),
			Pool: netip.MustParsePrefix("10.0.2.0/28"), // not within 10.0.1.0/24
		}},
	}})
	if err == nil {
		t.Fatal("expected pool-not-in-cidr rejection, got nil")
	}
	if m.VNetCount() != 0 {
		t.Fatalf("rejected vnet must not be stored, count=%d", m.VNetCount())
	}

	// Pool within CIDR is accepted.
	err = applyCmd(t, m, &Command{Kind: CmdVNetUpsert, VNetUpsert: &VNetUpsert{
		VNI: 200,
		Segments: []Segment{{
			CIDR: netip.MustParsePrefix("10.0.1.0/24"),
			Pool: netip.MustParsePrefix("10.0.1.16/28"),
		}},
	}})
	if err != nil {
		t.Fatalf("valid vnet rejected: %v", err)
	}
	if m.VNetCount() != 1 {
		t.Fatalf("vnet count = %d, want 1", m.VNetCount())
	}
}

// TestSessionCreateAssignsDistinctIPs verifies the post-2PC invariant: Apply
// allocates a free IP deterministically, so two sessions never share one — by
// construction, without any pre-selection or collision check.
func TestSessionCreateAssignsDistinctIPs(t *testing.T) {
	m := NewMeshState()
	seedVNet(t, m, 1, 2)
	now := time.Now().UnixNano()

	ipA, err := applyCreate(t, m, &SessionCreate{SessionID: sid(1), PubKey: pub(1), VNI: 200, LeaseTTL: time.Hour, Now: now})
	if err != nil {
		t.Fatalf("create A: %v", err)
	}
	ipB, err := applyCreate(t, m, &SessionCreate{SessionID: sid(2), PubKey: pub(2), VNI: 200, LeaseTTL: time.Hour, Now: now})
	if err != nil {
		t.Fatalf("create B: %v", err)
	}
	if !ipA.IsValid() || !ipB.IsValid() {
		t.Fatalf("invalid IPs: A=%s B=%s", ipA, ipB)
	}
	if ipA == ipB {
		t.Fatalf("two sessions got the same IP %s", ipA)
	}
	if m.SessionCount() != 2 {
		t.Fatalf("session count = %d, want 2", m.SessionCount())
	}
}

// TestSessionCreatePoolExhausted verifies ErrNoAddress when the pool has no
// free address left.
func TestSessionCreatePoolExhausted(t *testing.T) {
	m := NewMeshState()
	// Tiny pool: 10.0.1.16/30 = .16-.19, .16 is the network addr → 3 usable.
	if err := applyCmd(t, m, &Command{Kind: CmdVNetUpsert, VNetUpsert: &VNetUpsert{
		VNI: 200, Version: 1,
		Segments: []Segment{{
			CIDR:     netip.MustParsePrefix("10.0.1.0/24"),
			Pool:     netip.MustParsePrefix("10.0.1.16/30"),
			Reserved: []netip.Addr{netip.MustParseAddr("10.0.1.16")},
		}},
	}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// /30 = .16-.19; .16 reserved → .17, .18, .19 usable (3 free).
	now := time.Now().UnixNano()
	for i := byte(1); i <= 4; i++ {
		applyCmd(t, m, &Command{Kind: CmdKeyGrant, KeyGrant: &KeyGrant{VNI: 200, PubKey: pub(i)}})
		_, err := applyCreate(t, m, &SessionCreate{SessionID: sid(i), PubKey: pub(i), VNI: 200, LeaseTTL: time.Hour, Now: now})
		if i <= 3 && err != nil {
			t.Fatalf("create %d unexpectedly failed: %v", i, err)
		}
		if i == 4 && err == nil { // 4th exhausts the 3-address pool
			t.Fatal("expected ErrNoAddress on exhausted pool, got nil")
		}
	}
}

func TestSessionReplaceKeepsOneSessionPerPubKey(t *testing.T) {
	m := NewMeshState()
	seedVNet(t, m, 9)
	now := time.Now().UnixNano()

	if _, err := applyCreate(t, m, &SessionCreate{SessionID: sid(1), PubKey: pub(9), VNI: 200, LeaseTTL: time.Hour, Now: now}); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Replace with a new session for the same pubkey (IP allocated in Apply).
	repl := SessionReplace{New: SessionCreate{
		SessionID: sid(2), PubKey: pub(9), VNI: 200, LeaseTTL: time.Hour, Now: now,
	}}
	if err := applyCmd(t, m, &Command{Kind: CmdSessionReplace, SessionReplace: &repl}); err != nil {
		t.Fatalf("replace: %v", err)
	}

	if m.SessionCount() != 1 {
		t.Fatalf("session count = %d, want 1 after replace", m.SessionCount())
	}
	got, ok := m.SessionByPubKey(pub(9))
	if !ok {
		t.Fatal("pubkey lost its session after replace")
	}
	if got.SessionID != sid(2) {
		t.Fatalf("replace kept old session %v, want new %v", got.SessionID, sid(2))
	}
}

func TestKeyRevokeCascadesSessionDrop(t *testing.T) {
	m := NewMeshState()
	now := time.Now().UnixNano()

	// vnet + grant, so revoke has a key table to mutate.
	if err := applyCmd(t, m, &Command{Kind: CmdVNetUpsert, VNetUpsert: &VNetUpsert{
		VNI: 200,
		Segments: []Segment{{
			CIDR: netip.MustParsePrefix("10.0.1.0/24"),
			Pool: netip.MustParsePrefix("10.0.1.16/28"),
		}},
	}}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := applyCmd(t, m, &Command{Kind: CmdKeyGrant, KeyGrant: &KeyGrant{
		VNI: 200, PubKey: pub(5),
	}}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	create := SessionCreate{
		SessionID: sid(1), PubKey: pub(5), VNI: 200,
		LeaseTTL: time.Hour, Now: now,
	}
	if err := applyCmd(t, m, &Command{Kind: CmdSessionCreate, SessionCreate: &create}); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Revoke must remove both the grant and the live session.
	if err := applyCmd(t, m, &Command{Kind: CmdKeyRevoke, KeyRevoke: &KeyRevoke{
		VNI: 200, PubKey: pub(5),
	}}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if m.SessionCount() != 0 {
		t.Fatalf("revoke did not cascade drop; session count = %d", m.SessionCount())
	}
	if _, ok := m.SessionByPubKey(pub(5)); ok {
		t.Fatal("pubkey still resolves to a session after revoke")
	}
}

func TestBatchAppliesAllSubCommands(t *testing.T) {
	m := NewMeshState()
	seedVNet(t, m, 1, 2)
	now := time.Now().UnixNano()

	batch := []Command{
		{Kind: CmdSessionCreate, SessionCreate: &SessionCreate{
			SessionID: sid(1), PubKey: pub(1), VNI: 200, LeaseTTL: time.Hour, Now: now,
		}},
		{Kind: CmdSessionCreate, SessionCreate: &SessionCreate{
			SessionID: sid(2), PubKey: pub(2), VNI: 200, LeaseTTL: time.Hour, Now: now,
		}},
	}
	if err := applyCmd(t, m, &Command{Kind: CmdBatch, Batch: batch}); err != nil {
		t.Fatalf("batch: %v", err)
	}
	if m.SessionCount() != 2 {
		t.Fatalf("batch applied %d sessions, want 2", m.SessionCount())
	}
}

func TestSnapshotRestoreRoundTrip(t *testing.T) {
	m := NewMeshState()
	seedVNet(t, m, 7)
	now := time.Now().UnixNano()
	create := SessionCreate{
		SessionID: sid(7), PubKey: pub(7), VNI: 200, LeaseTTL: time.Hour, Now: now,
	}
	if err := applyCmd(t, m, &Command{Kind: CmdSessionCreate, SessionCreate: &create}); err != nil {
		t.Fatalf("create: %v", err)
	}

	blob, err := m.SnapshotBytes()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	restored := NewMeshState()
	if err := restored.RestoreBytes(blob); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if restored.SessionCount() != 1 {
		t.Fatalf("restored session count = %d, want 1", restored.SessionCount())
	}
	// Reverse index must be rebuilt, not left empty.
	if _, ok := restored.SessionByPubKey(pub(7)); !ok {
		t.Fatal("restore did not rebuild pubkey->session index")
	}
}
