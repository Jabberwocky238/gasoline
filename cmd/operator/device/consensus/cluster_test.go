package consensus

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// testCluster spins up an N-node consensus cluster over real QUIC transports
// on loopback, bootstrapped as a single group.
type testCluster struct {
	t     *testing.T
	nodes []*Node
}

// freePort grabs an OS-assigned UDP port and returns "127.0.0.1:port".
func freePort(t *testing.T) string {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	c, err := net.ListenUDP("udp", a)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := c.LocalAddr().String()
	_ = c.Close() // QUIC will re-bind it; race window is negligible on loopback
	return addr
}

// newTestCluster builds and starts n nodes. Node 0 bootstraps the group.
func newTestCluster(t *testing.T, n int) *testCluster {
	t.Helper()
	peers := make([]Peer, n)
	addrs := make([]string, n)
	for i := 0; i < n; i++ {
		addrs[i] = freePort(t)
		peers[i] = Peer{ID: fmt.Sprintf("node-%d", i), Addr: addrs[i]}
	}

	tc := &testCluster{t: t}
	for i := 0; i < n; i++ {
		node, err := NewNode(Config{
			LocalID:            peers[i].ID,
			BindAddr:           addrs[i],
			Peers:              peers,
			Bootstrap:          i == 0, // only node 0 seeds the cluster
			HeartbeatTimeout:   100 * time.Millisecond,
			ElectionTimeout:    100 * time.Millisecond,
			LeaderLeaseTimeout: 80 * time.Millisecond,
			CommitTimeout:      20 * time.Millisecond,
			LogOutput:          io.Discard,
		})
		if err != nil {
			t.Fatalf("node %d: %v", i, err)
		}
		tc.nodes = append(tc.nodes, node)
	}
	t.Cleanup(tc.shutdown)
	return tc
}

func (tc *testCluster) shutdown() {
	for _, n := range tc.nodes {
		if n != nil {
			_ = n.Shutdown()
		}
	}
}

// waitLeader blocks until some node reports leadership, returning it.
func (tc *testCluster) waitLeader(timeout time.Duration) *Node {
	tc.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, n := range tc.nodes {
			if n != nil && n.IsLeader() {
				return n
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	tc.t.Fatalf("no leader within %s", timeout)
	return nil
}

// aliveNodes returns nodes that have not been shut down (non-nil).
func (tc *testCluster) aliveNodes() []*Node {
	var out []*Node
	for _, n := range tc.nodes {
		if n != nil {
			out = append(out, n)
		}
	}
	return out
}

// proposeSession commits one session through node (leader or follower). The IP
// is allocated in Apply (deterministic first-free), so it seeds a vnet + pool +
// key grant for this pubkey first. The pool /24 gives plenty of addresses so
// concurrent sessions never exhaust it.
func proposeSession(t *testing.T, node *Node, id byte, _ string) error {
	t.Helper()
	p := pub(id)
	// Seed vnet 200 with a pool (idempotent: version 1 upsert; re-applying with
	// the same version is a no-op) and grant this key.
	_ = node.Propose(&Command{Kind: CmdVNetUpsert, VNetUpsert: &VNetUpsert{
		VNI: 200, Version: 1,
		Segments: []Segment{{
			CIDR: netip.MustParsePrefix("10.0.1.0/24"),
			Pool: netip.MustParsePrefix("10.0.1.0/24"),
		}},
	}}, 2*time.Second)
	_ = node.Propose(&Command{Kind: CmdKeyGrant, KeyGrant: &KeyGrant{VNI: 200, PubKey: p}}, 2*time.Second)
	return node.Propose(&Command{
		Kind: CmdSessionCreate,
		SessionCreate: &SessionCreate{
			SessionID: sid(id),
			PubKey:    p,
			VNI:       200,
			LeaseTTL:  time.Hour,
			Now:       time.Now().UnixNano(),
		},
	}, 2*time.Second)
}

// waitReplicated blocks until every alive node's FSM has want sessions.
func waitReplicated(t *testing.T, nodes []*Node, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ok := true
		for _, n := range nodes {
			if n.State().SessionCount() != want {
				ok = false
				break
			}
		}
		if ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	counts := make([]int, len(nodes))
	for i, n := range nodes {
		counts[i] = n.State().SessionCount()
	}
	t.Fatalf("replication did not converge to %d within %s; got %v", want, timeout, counts)
}

// --------------- P0: bootstrap, elect, replicate ---------------

func TestP0_BootstrapElectsLeader(t *testing.T) {
	tc := newTestCluster(t, 3)
	leader := tc.waitLeader(5 * time.Second)
	if leader == nil {
		t.Fatal("no leader")
	}
	// Exactly one leader.
	count := 0
	for _, n := range tc.nodes {
		if n.IsLeader() {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("leader count = %d, want 1", count)
	}
}

func TestP0_LogReplicatesToAllNodes(t *testing.T) {
	tc := newTestCluster(t, 3)
	leader := tc.waitLeader(5 * time.Second)

	if err := proposeSession(t, leader, 1, "10.0.1.17"); err != nil {
		t.Fatalf("propose: %v", err)
	}
	waitReplicated(t, tc.nodes, 1, 3*time.Second)
}

// TestP0_FollowerProposeForwardsToLeader verifies the follower->leader forward
// path (PRD §2.3): a Propose issued on a follower is shipped to the leader,
// committed, and replicated back to every node — so any operator can serve a
// handshake, not just the leader.
func TestP0_FollowerProposeForwardsToLeader(t *testing.T) {
	tc := newTestCluster(t, 3)
	tc.waitLeader(5 * time.Second)

	var follower *Node
	for _, n := range tc.nodes {
		if !n.IsLeader() {
			follower = n
			break
		}
	}
	if follower == nil {
		t.Fatal("no follower")
	}
	// Proposing on the follower must succeed via forwarding, and the committed
	// session must replicate to all nodes.
	if err := proposeSession(t, follower, 2, "10.0.1.18"); err != nil {
		t.Fatalf("follower Propose (forwarded) failed: %v", err)
	}
	waitReplicated(t, tc.nodes, 1, 3*time.Second)
}
