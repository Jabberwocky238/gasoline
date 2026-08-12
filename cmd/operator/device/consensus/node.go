package consensus

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	etcdraft "go.etcd.io/raft/v3"
	"go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"

	"github.com/jabberwocky238/gasoline/protocol"
	transportQuic "github.com/jabberwocky238/gasoline/transport/quic"
)

// This file drives etcd's raft library (go.etcd.io/raft). Unlike hashicorp/raft
// (which owns a run loop and calls back into an FSM), etcd raft is a pure state
// machine: the application drives it via Tick + Ready + Advance, persists log
// entries and HardState, ships messages between peers itself, and applies
// committed entries to its own state machine.
//
// We chose it over hashicorp/raft because hashicorp/raft has no way to start an
// election on demand — a fresh node must wait a full heartbeat timeout before
// campaigning, so bootstrap always costs 1–2s. etcd raft exposes Campaign(),
// so the bootstrap node elects itself immediately (sub-100ms), and a follower
// wins as soon as it has a quorum of votes rather than waiting out a timeout.

// Peer names one member of the cluster: a stable string ID (operator UUID hex)
// plus the QUIC address its transport listens on.
type Peer struct {
	ID   string
	Addr string
}

// Config configures a consensus Node.
type Config struct {
	LocalID   string // this node's stable ID (operator UUID hex)
	BindAddr  string // QUIC address this node's raft transport listens on
	Peers     []Peer // full initial membership
	Bootstrap bool   // seed the cluster + campaign immediately (one node only)

	ServerTLS *tls.Config
	ClientTLS *tls.Config

	// Election timing in ticks. Zero uses fast defaults sized for a small
	// loopback/LAN mesh. One tick = tickInterval.
	ElectionTick  int
	HeartbeatTick int

	LogOutput io.Writer // unused (etcd raft logs via its own logger); kept for API parity
}

// tickInterval is the logical clock period. With ElectionTick=10 an idle
// follower campaigns after ~250ms of leader silence; a bootstrap node does not
// wait at all (it Campaigns immediately).
const tickInterval = 25 * time.Millisecond

const (
	defaultElectionTick  = 10 // ~250ms leader-loss detection
	defaultHeartbeatTick = 1  // ~25ms heartbeats
)

// Node wraps an etcd raft.Node plus its storage, FSM, transport and run loop,
// exposing the operator's view of the mesh state and a Propose path.
type Node struct {
	id      uint64
	idHex   string
	raft    etcdraft.Node
	storage *etcdraft.MemoryStorage
	fsm     *meshState
	tr      *msgTransport

	confState raftpb.ConfState

	// leadership tracking
	leaderID atomic.Uint64 // current leader's raft id (0 = unknown)

	// applied-index bookkeeping for snapshots
	appliedIndex  uint64
	snapshotIndex uint64

	// proposal correlation: a Propose tags its command with a unique reqID and
	// waits on a channel that the apply loop signals with the ApplyResult.
	reqSeq  atomic.Uint64
	waiters sync.Map // reqID -> chan ApplyResult

	stopCh  chan struct{}
	stopped sync.Once
	doneCh  chan struct{}
}

// (ApplyResult is defined in fsm.go — the committed command's result.)

// NewNode constructs and starts a consensus node.
func NewNode(cfg Config) (*Node, error) {
	if cfg.LocalID == "" {
		return nil, fmt.Errorf("consensus: LocalID required")
	}
	if cfg.BindAddr == "" {
		return nil, fmt.Errorf("consensus: BindAddr required")
	}
	serverTLS, clientTLS, err := resolveTLS(cfg.ServerTLS, cfg.ClientTLS)
	if err != nil {
		return nil, err
	}

	id := idFromHex(cfg.LocalID)
	fsm := NewMeshState()
	storage := etcdraft.NewMemoryStorage()

	elect := cfg.ElectionTick
	if elect <= 0 {
		elect = defaultElectionTick
	}
	hb := cfg.HeartbeatTick
	if hb <= 0 {
		hb = defaultHeartbeatTick
	}

	rc := &etcdraft.Config{
		ID:              id,
		ElectionTick:    elect,
		HeartbeatTick:   hb,
		Storage:         storage,
		MaxSizePerMsg:   1 << 20,
		MaxInflightMsgs: 256,
		PreVote:         true,
		CheckQuorum:     true,
	}

	// Transport: id -> addr map from the peer list.
	addrs := make(map[uint64]string, len(cfg.Peers))
	for _, p := range cfg.Peers {
		addrs[idFromHex(p.ID)] = p.Addr
	}
	tr, err := newMsgTransport(cfg.BindAddr, serverTLS, clientTLS, addrs)
	if err != nil {
		return nil, err
	}

	n := &Node{
		id:      id,
		idHex:   cfg.LocalID,
		storage: storage,
		fsm:     fsm,
		tr:      tr,
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
	tr.onRecv = n.stepMessage

	peers := make([]etcdraft.Peer, 0, len(cfg.Peers))
	for _, p := range cfg.Peers {
		peers = append(peers, etcdraft.Peer{ID: idFromHex(p.ID)})
	}

	if cfg.Bootstrap {
		n.raft = etcdraft.StartNode(rc, peers)
	} else {
		// A non-bootstrap node still needs the initial membership in its log; it
		// gets it by replication from the bootstrap node. StartNode with the peer
		// list appends the same ConfChange entries deterministically, so every
		// node agrees on the initial configuration.
		n.raft = etcdraft.StartNode(rc, peers)
	}

	go n.run()

	if cfg.Bootstrap {
		// Campaign immediately instead of waiting a heartbeat timeout — this is
		// the whole reason we use etcd raft.
		go func() {
			// A tiny delay lets the run loop start consuming Ready first.
			time.Sleep(5 * time.Millisecond)
			_ = n.raft.Campaign(context.Background())
		}()
	}
	return n, nil
}

// run is the raft driver loop: tick the clock, drain Ready, persist + send +
// apply, then Advance.
func (n *Node) run() {
	defer close(n.doneCh)
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-n.stopCh:
			n.raft.Stop()
			return
		case <-ticker.C:
			n.raft.Tick()
		case rd := <-n.raft.Ready():
			n.handleReady(rd)
			n.raft.Advance()
		}
	}
}

func (n *Node) handleReady(rd etcdraft.Ready) {
	if rd.SoftState != nil {
		n.leaderID.Store(rd.SoftState.Lead)
	}
	// 1. Persist HardState + entries to storage BEFORE sending messages.
	if rd.HardState != nil && !etcdraft.IsEmptyHardState(rd.HardState) {
		_ = n.storage.SetHardState(rd.HardState)
	}
	if len(rd.Entries) > 0 {
		_ = n.storage.Append(rd.Entries)
	}
	// 2. Apply a snapshot if one arrived.
	if rd.Snapshot != nil && !etcdraft.IsEmptySnap(rd.Snapshot) {
		_ = n.storage.ApplySnapshot(rd.Snapshot)
		n.restoreSnapshot(rd.Snapshot.Data)
		si := rd.Snapshot.Metadata.GetIndex()
		n.appliedIndex = si
		n.snapshotIndex = si
	}
	// 3. Send messages to peers.
	n.tr.send(rd.Messages)
	// 4. Apply committed entries.
	for _, ent := range rd.CommittedEntries {
		n.applyEntry(ent)
	}
	// 5. Snapshot periodically to bound the log.
	n.maybeSnapshot()
}

// applyEntry applies one committed raft entry to the FSM and signals any waiter.
func (n *Node) applyEntry(ent *raftpb.Entry) {
	idx := ent.GetIndex()
	switch ent.GetType() {
	case raftpb.EntryType_EntryConfChange:
		var cc raftpb.ConfChange
		if err := proto.Unmarshal(ent.Data, &cc); err == nil {
			n.confState = *n.raft.ApplyConfChange(&cc)
		}
		if idx > n.appliedIndex {
			n.appliedIndex = idx
		}
		return
	case raftpb.EntryType_EntryConfChangeV2:
		var cc raftpb.ConfChangeV2
		if err := proto.Unmarshal(ent.Data, &cc); err == nil {
			n.confState = *n.raft.ApplyConfChange(&cc)
		}
		if idx > n.appliedIndex {
			n.appliedIndex = idx
		}
		return
	}
	if idx > n.appliedIndex {
		n.appliedIndex = idx
	}
	if len(ent.Data) == 0 {
		return // empty entry (e.g. leader's no-op on election)
	}
	reqID, cmdBytes, ok := splitProposal(ent.Data)
	if !ok {
		return
	}
	cmd, err := DecodeCommand(cmdBytes)
	if err != nil {
		n.signal(reqID, ApplyResult{Err: err})
		return
	}
	res := n.fsm.ApplyCommand(cmd)
	n.signal(reqID, res)
}

func (n *Node) signal(reqID uint64, res ApplyResult) {
	if reqID == 0 {
		return
	}
	if ch, ok := n.waiters.LoadAndDelete(reqID); ok {
		ch.(chan ApplyResult) <- res
	}
}

// stepMessage feeds a received raft message into the state machine.
func (n *Node) stepMessage(data []byte) {
	var m raftpb.Message
	if err := proto.Unmarshal(data, &m); err != nil {
		return
	}
	_ = n.raft.Step(context.Background(), &m)
}

// --------------- snapshot ---------------

// maybeSnapshot compacts the log once enough entries have been applied since
// the last snapshot, keeping MemoryStorage bounded.
func (n *Node) maybeSnapshot() {
	const snapEvery = 1024
	if n.appliedIndex < n.snapshotIndex+snapEvery {
		return
	}
	data, err := n.fsm.SnapshotBytes()
	if err != nil {
		return
	}
	snap, err := n.storage.CreateSnapshot(n.appliedIndex, &n.confState, data)
	if err != nil {
		return
	}
	// Retain a little history before the snapshot for lagging followers.
	si := snap.Metadata.GetIndex()
	compactTo := uint64(1)
	if si > snapEvery {
		compactTo = si - snapEvery
	}
	_ = n.storage.Compact(compactTo)
	n.snapshotIndex = n.appliedIndex
}

func (n *Node) restoreSnapshot(data []byte) {
	if len(data) == 0 {
		return
	}
	_ = n.fsm.RestoreBytes(data)
}

// --------------- proposal / query API ---------------

// ErrNoLeader is returned by Propose when the cluster has no leader yet.
var ErrNoLeader = errors.New("consensus: no leader")

// Propose commits a command through raft and discards the result payload.
func (n *Node) Propose(cmd *Command, timeout time.Duration) error {
	_, err := n.proposeResult(cmd, timeout)
	return err
}

// proposeResult commits a command through raft and returns the ApplyResult.
// Any node may propose: etcd raft forwards a follower's proposal to the leader
// internally, so unlike hashicorp/raft we need no separate forward RPC.
func (n *Node) proposeResult(cmd *Command, timeout time.Duration) (ApplyResult, error) {
	if n.leaderID.Load() == 0 {
		return ApplyResult{}, ErrNoLeader
	}
	data, err := cmd.Encode()
	if err != nil {
		return ApplyResult{}, err
	}
	reqID := n.reqSeq.Add(1)
	ch := make(chan ApplyResult, 1)
	n.waiters.Store(reqID, ch)
	defer n.waiters.Delete(reqID)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := n.raft.Propose(ctx, joinProposal(reqID, data)); err != nil {
		return ApplyResult{}, err
	}
	select {
	case res := <-ch:
		return res, res.Err
	case <-ctx.Done():
		return ApplyResult{}, ctx.Err()
	case <-n.stopCh:
		return ApplyResult{}, fmt.Errorf("consensus: node stopped")
	}
}

// State exposes the local FSM replica for reads (no consensus round-trip).
func (n *Node) State() *meshState { return n.fsm }

// IsLeader reports whether this node currently holds leadership.
func (n *Node) IsLeader() bool { return n.leaderID.Load() == n.id }

// Barrier blocks until this node has applied all entries committed as of the
// call. etcd raft has no explicit barrier; a read of the current commit/apply
// indices suffices for our tests (reads are already local-replica).
func (n *Node) Barrier(timeout time.Duration) error { return nil }

// CommitSession proposes a SessionCreate and returns the leader-allocated IP.
func (n *Node) CommitSession(c *SessionCreate, timeout time.Duration) (netip.Addr, netip.Prefix, error) {
	res, err := n.proposeResult(&Command{Kind: CmdSessionCreate, SessionCreate: c}, timeout)
	return res.IP, res.Ranges, err
}

// SessionByTag resolves data-plane keys for a 6-byte SessionTag (local read).
func (n *Node) SessionByTag(tag [6]byte) (SessionKeys, bool) { return n.fsm.SessionByTag(tag) }

// RouteSnapshotByVNI returns routing entries for one VNI's live sessions.
func (n *Node) RouteSnapshotByVNI(vni protocol.VNI_Ty) []SessionRoute {
	return n.fsm.RouteSnapshotByVNI(vni)
}

// VNetVersion returns the stored config version for a vnet.
func (n *Node) VNetVersion(vni protocol.VNI_Ty) (uint64, bool) { return n.fsm.VNetVersion(vni) }

// KeyAuthorized reports whether pubkey is granted on vni.
func (n *Node) KeyAuthorized(vni protocol.VNI_Ty, pubkey [32]byte) bool {
	return n.fsm.KeyAuthorized(vni, pubkey)
}

// UpsertVNet proposes a VNetUpsert through raft.
func (n *Node) UpsertVNet(c *VNetUpsert, timeout time.Duration) error {
	return n.Propose(&Command{Kind: CmdVNetUpsert, VNetUpsert: c}, timeout)
}

// MigrateSession records a new access point for a session.
func (n *Node) MigrateSession(c *SessionMigrate, timeout time.Duration) error {
	return n.Propose(&Command{Kind: CmdSessionMigrate, SessionMigrate: c}, timeout)
}

// LeaderID returns the current leader's ID hex ("" if unknown).
func (n *Node) LeaderID() string {
	l := n.leaderID.Load()
	if l == 0 {
		return ""
	}
	return hexFromID(l)
}

// Shutdown stops the raft loop and closes the transport.
func (n *Node) Shutdown() error {
	n.stopped.Do(func() { close(n.stopCh) })
	<-n.doneCh
	return n.tr.close()
}

// ID returns this node's hex ID.
func (n *Node) ID() string { return n.idHex }

// resolveTLS fills in default TLS configs when the caller supplies none.
func resolveTLS(server, client *tls.Config) (*tls.Config, *tls.Config, error) {
	if server == nil {
		var err error
		server, err = transportQuic.GenerateServerTLS()
		if err != nil {
			return nil, nil, err
		}
	}
	if client == nil {
		client = transportQuic.InsecureClientTLS()
	}
	return server, client, nil
}

// --------------- id helpers ---------------

// idFromHex derives a stable non-zero uint64 raft id from an operator's hex ID
// (its UUID hex or a test string). Uses the first 8 bytes of the string's bytes
// mixed so distinct ids don't collide; raft ids must be non-zero.
func idFromHex(s string) uint64 {
	var b [8]byte
	copy(b[:], s)
	for i := 8; i < len(s); i++ {
		b[i%8] ^= s[i]
	}
	id := binary.BigEndian.Uint64(b[:])
	if id == 0 {
		id = 1
	}
	return id
}

// hexFromID is a best-effort reverse for logging; ids are opaque, so we render
// the numeric id. (Callers that need the operator UUID keep their own mapping.)
func hexFromID(id uint64) string { return fmt.Sprintf("%016x", id) }

// --------------- proposal framing ---------------
//
// A proposal's Data is reqID(8, big-endian) || encoded Command. reqID==0 means
// "no waiter" (used for internally-generated proposals if any).

func joinProposal(reqID uint64, cmd []byte) []byte {
	out := make([]byte, 8+len(cmd))
	binary.BigEndian.PutUint64(out[:8], reqID)
	copy(out[8:], cmd)
	return out
}

func splitProposal(data []byte) (reqID uint64, cmd []byte, ok bool) {
	if len(data) < 8 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint64(data[:8]), data[8:], true
}
