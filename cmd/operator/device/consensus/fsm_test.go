package consensus

import (
	"net/netip"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/jabberwocky238/gasoline/protocol"
)

// applyCmd runs a command straight through the FSM (no raft), returning the
// per-command error. Mirrors what raft.Apply would deliver.
func applyCmd(t *testing.T, m *meshState, cmd *Command) error {
	t.Helper()
	data, err := cmd.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	res := m.Apply(&raft.Log{Data: data})
	ar, ok := res.(ApplyResult)
	if !ok {
		t.Fatalf("Apply returned %T, want ApplyResult", res)
	}
	return ar.Err
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

func TestSessionCreateRejectsDuplicateIP(t *testing.T) {
	m := NewMeshState()
	now := time.Now().UnixNano()
	base := SessionCreate{
		VNI:      200,
		IP:       netip.MustParseAddr("10.0.1.17"),
		LeaseTTL: time.Hour,
		Now:      now,
	}

	a := base
	a.SessionID, a.PubKey, a.CID = sid(1), pub(1), protocol.CID_Ty{1}
	if err := applyCmd(t, m, &Command{Kind: CmdSessionCreate, SessionCreate: &a}); err != nil {
		t.Fatalf("first create: %v", err)
	}

	// Same IP, different session — must collide.
	b := base
	b.SessionID, b.PubKey, b.CID = sid(2), pub(2), protocol.CID_Ty{2}
	if err := applyCmd(t, m, &Command{Kind: CmdSessionCreate, SessionCreate: &b}); err == nil {
		t.Fatal("expected duplicate-IP rejection, got nil")
	}
	if m.SessionCount() != 1 {
		t.Fatalf("session count = %d, want 1", m.SessionCount())
	}
}

func TestSessionReplaceKeepsOneSessionPerPubKey(t *testing.T) {
	m := NewMeshState()
	now := time.Now().UnixNano()

	first := SessionCreate{
		SessionID: sid(1), PubKey: pub(9), CID: protocol.CID_Ty{1}, VNI: 200,
		IP: netip.MustParseAddr("10.0.1.17"), LeaseTTL: time.Hour, Now: now,
	}
	if err := applyCmd(t, m, &Command{Kind: CmdSessionCreate, SessionCreate: &first}); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Replace with a new session for the same pubkey at a different IP.
	repl := SessionReplace{New: SessionCreate{
		SessionID: sid(2), PubKey: pub(9), CID: protocol.CID_Ty{1}, VNI: 200,
		IP: netip.MustParseAddr("10.0.1.18"), LeaseTTL: time.Hour, Now: now,
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
		SessionID: sid(1), PubKey: pub(5), CID: protocol.CID_Ty{1}, VNI: 200,
		IP: netip.MustParseAddr("10.0.1.17"), LeaseTTL: time.Hour, Now: now,
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
	now := time.Now().UnixNano()

	batch := []Command{
		{Kind: CmdSessionCreate, SessionCreate: &SessionCreate{
			SessionID: sid(1), PubKey: pub(1), VNI: 200,
			IP: netip.MustParseAddr("10.0.1.17"), LeaseTTL: time.Hour, Now: now,
		}},
		{Kind: CmdSessionCreate, SessionCreate: &SessionCreate{
			SessionID: sid(2), PubKey: pub(2), VNI: 200,
			IP: netip.MustParseAddr("10.0.1.18"), LeaseTTL: time.Hour, Now: now,
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
	now := time.Now().UnixNano()
	create := SessionCreate{
		SessionID: sid(7), PubKey: pub(7), CID: protocol.CID_Ty{7}, VNI: 200,
		IP: netip.MustParseAddr("10.0.1.17"), LeaseTTL: time.Hour, Now: now,
	}
	if err := applyCmd(t, m, &Command{Kind: CmdSessionCreate, SessionCreate: &create}); err != nil {
		t.Fatalf("create: %v", err)
	}

	snap, err := m.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	sink := &memSink{}
	if err := snap.Persist(sink); err != nil {
		t.Fatalf("persist: %v", err)
	}

	restored := NewMeshState()
	if err := restored.Restore(newReadCloser(sink.data)); err != nil {
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
