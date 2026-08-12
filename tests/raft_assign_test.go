package tests

import (
	"net"
	"net/netip"
	"testing"
	"time"

	operator "github.com/jabberwocky238/gasoline/cmd/operator/device"
	"github.com/jabberwocky238/gasoline/cmd/operator/device/consensus"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/noise"
	"github.com/jabberwocky238/gasoline/transport"
	"github.com/jabberwocky238/gasoline/transport/udp"
	"github.com/sirupsen/logrus"
)

// freeUDPAddr grabs an OS-assigned UDP port for the Raft transport.
func freeUDPAddr(t *testing.T) string {
	t.Helper()
	a, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	c, err := net.ListenUDP("udp", a)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := c.LocalAddr().String()
	_ = c.Close()
	return addr
}

// TestP4_RaftBackedAssignment stands up a single-node Raft cluster, seeds a
// vnet with an allocatable pool + two key grants, attaches it to an operator,
// and dials two clients. The IPs and SessionIDs are allocated by the Raft
// path (raftAllocator: PickIP from the FSM + SessionCreate commit), not by any
// preset — proving the consensus-backed 2PC works end to end.
func TestP4_RaftBackedAssignment(t *testing.T) {
	const vni protocol.VNI_Ty = 200

	// Two client identities + shared operator static key.
	privA, pubA, _ := noise.GenerateKey()
	privB, pubB, _ := noise.GenerateKey()
	serverPriv, serverPub, _ := noise.GenerateKey()

	// --- 1-node Raft cluster ---
	raftAddr := freeUDPAddr(t)
	node, err := consensus.NewNode(consensus.Config{
		LocalID:   "op-0",
		BindAddr:  raftAddr,
		Peers:     []consensus.Peer{{ID: "op-0", Addr: raftAddr}},
		Bootstrap: true,
	})
	if err != nil {
		t.Fatalf("consensus node: %v", err)
	}
	defer node.Shutdown()

	// Wait for leadership.
	deadline := time.Now().Add(5 * time.Second)
	for !node.IsLeader() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !node.IsLeader() {
		t.Fatal("node never became leader")
	}

	// Seed the mesh state: a vnet with a pool, and two key grants.
	if err := node.Propose(&consensus.Command{Kind: consensus.CmdVNetUpsert, VNetUpsert: &consensus.VNetUpsert{
		VNI: vni,
		Segments: []consensus.Segment{{
			CIDR:     netip.MustParsePrefix("10.0.200.0/24"),
			Pool:     netip.MustParsePrefix("10.0.200.16/28"),
			Reserved: []netip.Addr{netip.MustParseAddr("10.0.200.16")}, // network addr
		}},
	}}, 2*time.Second); err != nil {
		t.Fatalf("vnet upsert: %v", err)
	}
	for _, pub := range []noise.PublicKey{pubA, pubB} {
		var p [32]byte = pub
		if err := node.Propose(&consensus.Command{Kind: consensus.CmdKeyGrant, KeyGrant: &consensus.KeyGrant{
			VNI: vni, PubKey: p,
		}}, 2*time.Second); err != nil {
			t.Fatalf("key grant: %v", err)
		}
	}

	// --- operator with the Raft allocator attached (no preset) ---
	uuid := [16]byte{0xA0}
	op, err := operator.New(&operator.StaticOperatorConfig{
		UUID:       &uuid,
		StaticPriv: serverPriv,
		ClientListeners: []operator.ListenerSpec{
			{Transport: "udp", Addr: "127.0.0.1:0"},
		},
		OpListenAddr: "127.0.0.1:0",
		Network: map[protocol.VNI_Ty]operator.StaticOperatorVNetConfig{
			vni: {
				VNI:            vni,
				CIDR:           "10.0.200.0/24",
				AuthorizedKeys: map[noise.PublicKey]struct{}{pubA: {}, pubB: {}},
				// No PresetKeyMap: allocation comes from the Raft pool.
			},
		},
		LogLevel: logrus.ErrorLevel,
	})
	if err != nil {
		t.Fatalf("operator.New: %v", err)
	}
	op.AttachConsensus(node)
	if err := op.Start(); err != nil {
		t.Fatalf("operator.Start: %v", err)
	}
	defer op.Close()

	// --- dial both clients; each gets a pool IP + Raft SessionID ---
	idA := transport.ClientIdentity{Priv: privA, Pub: pubA, ServerPub: serverPub}
	idB := transport.ClientIdentity{Priv: privB, Pub: pubB, ServerPub: serverPub}

	connA, scA := dialAndAssign(t, udp.NewDialer(protocol.NewPresetSessionConfig(vni), idA), op.ClientAddr(), idA, vni)
	defer connA.Close()
	connB, scB := dialAndAssign(t, udp.NewDialer(protocol.NewPresetSessionConfig(vni), idB), op.ClientAddr(), idB, vni)
	defer connB.Close()

	// Both IPs must be inside the pool and distinct.
	pool := netip.MustParsePrefix("10.0.200.16/28")
	if !pool.Contains(scA.IP) || !pool.Contains(scB.IP) {
		t.Fatalf("assigned IPs not in pool: A=%s B=%s", scA.IP, scB.IP)
	}
	if scA.IP == scB.IP {
		t.Fatalf("two clients got the same IP %s", scA.IP)
	}
	// SessionIDs are cluster-minted and distinct.
	if scA.SessionID == scB.SessionID || scA.SessionID.IsZero() || scB.SessionID.IsZero() {
		t.Fatalf("bad SessionIDs: A=%s B=%s", scA.SessionID, scB.SessionID)
	}

	// The commits landed in Raft: two live sessions in the FSM.
	if got := node.State().SessionCount(); got != 2 {
		t.Fatalf("FSM session count = %d, want 2", got)
	}

	// Data plane still works: A -> B through the operator's L3 forwarder.
	pkt := makeIPv4Packet(scA.IP, scB.IP, []byte("hello"))
	recv := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 65535)
		n, err := connB.ReadPacket(buf)
		if err == nil {
			recv <- append([]byte(nil), buf[:n]...)
		}
	}()
	if err := connA.WritePacket(pkt); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case got := <-recv:
		if netip.AddrFrom4([4]byte{got[16], got[17], got[18], got[19]}) != scB.IP {
			t.Fatalf("packet delivered to wrong dst")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("packet not delivered A->B")
	}
}
