package tests

import (
	"net"
	"net/netip"
	"testing"
	"time"

	operator "github.com/jabberwocky238/gasoline/cmd/operator/device"
	"github.com/jabberwocky238/gasoline/cmd/operator/device/consensus"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/datacom"
	"github.com/jabberwocky238/gasoline/protocol/noise"
	"github.com/jabberwocky238/gasoline/transport"
	"github.com/jabberwocky238/gasoline/transport/udp"
	"github.com/sirupsen/logrus"
)

// TestG4_HopToAnotherOperator proves the core of G4: a client that handshook
// with operator A can send a data frame FROM A NEW SOURCE straight to operator
// B — which has never seen it handshake — and B decrypts it using the Raft-
// replicated session keys, migrates the access point, and forwards it. No
// re-handshake, no packet loss (PRD §5.4.3 / §6.4).
func TestG4_HopToAnotherOperator(t *testing.T) {
	const vni protocol.VNI_Ty = 200

	privA, pubA, _ := noise.GenerateKey()
	privB, pubB, _ := noise.GenerateKey()
	serverPriv, serverPub, _ := noise.GenerateKey()

	// --- single-node Raft cluster shared by both operators ---
	//
	// One node keeps the harness deterministic (no follower→leader forwarding,
	// which the assign path does not yet do). Both operators read/write the same
	// FSM, so B's operator sees A's session exactly as a replicated follower
	// would — the demux path under test is identical.
	raftAddr := freeUDPAddr(t)
	node, err := consensus.NewNode(consensus.Config{
		LocalID: "op-0", BindAddr: raftAddr, Peers: []consensus.Peer{{ID: "op-0", Addr: raftAddr}}, Bootstrap: true,
		HeartbeatTimeout: 100 * time.Millisecond, ElectionTimeout: 100 * time.Millisecond,
		LeaderLeaseTimeout: 80 * time.Millisecond, CommitTimeout: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	defer node.Shutdown()
	waitLeader(t, node)

	// Seed vnet + key grants (both clients authorized).
	mustPropose(t, node, &consensus.Command{Kind: consensus.CmdVNetUpsert, VNetUpsert: &consensus.VNetUpsert{
		VNI: vni,
		Segments: []consensus.Segment{{
			CIDR: netip.MustParsePrefix("10.0.200.0/24"),
			Pool: netip.MustParsePrefix("10.0.200.16/28"),
		}},
	}})
	for _, pub := range []noise.PublicKey{pubA, pubB} {
		var p [32]byte = pub
		mustPropose(t, node, &consensus.Command{Kind: consensus.CmdKeyGrant, KeyGrant: &consensus.KeyGrant{VNI: vni, PubKey: p}})
	}

	// --- two operators sharing the node + mesh static key ---
	uuidA := [16]byte{0xA0}
	uuidB := [16]byte{0xB0}
	opA := mkHopOperator(t, uuidA, serverPriv, vni, pubA, pubB)
	opA.AttachConsensus(node)
	mustStart(t, opA)
	defer opA.Close()
	opB := mkHopOperator(t, uuidB, serverPriv, vni, pubA, pubB)
	opB.AttachConsensus(node)
	mustStart(t, opB)
	defer opB.Close()
	node1 := node // alias: post-hop assertions read the shared FSM

	// Wire the underlay both ways so cross-PE forwarding works.
	apA, _ := netip.ParseAddrPort(opA.DataPlaneAddr())
	apB, _ := netip.ParseAddrPort(opB.DataPlaneAddr())
	opA.AddPeer(uuidB, apB)
	opB.AddPeer(uuidA, apA)

	// --- dial A on opA and B on opB (normal handshakes) ---
	idA := transport.ClientIdentity{Priv: privA, Pub: pubA, ServerPub: serverPub}
	idB := transport.ClientIdentity{Priv: privB, Pub: pubB, ServerPub: serverPub}

	dialedA, err := udp.NewDialer(protocol.NewPresetSessionConfig(vni), idA).Dial(opA.ClientAddr())
	if err != nil {
		t.Fatalf("A dial: %v", err)
	}
	defer dialedA.Conn.Close()
	scA, err := datacom.ClientAssign(dialedA.Conn, dialedA.Session, vni)
	if err != nil {
		t.Fatalf("A assign: %v", err)
	}

	connB, scB := dialAndAssign(t, udp.NewDialer(protocol.NewPresetSessionConfig(vni), idB), opB.ClientAddr(), idB, vni)
	defer connB.Close()

	t.Logf("A ip=%s @opA sid=%s | B ip=%s @opB sid=%s", scA.IP, scA.SessionID, scB.IP, scB.SessionID)

	// Wait until B's operator (node1) has A's session replicated in its FSM.
	waitFor(t, 3*time.Second, func() bool {
		_, ok := node1.SessionByTag(datacom.TagOf(scA.SessionID))
		return ok
	})

	// --- THE HOP: A sends a frame to opB's client listener from a NEW socket,
	// destined to B. opB must serve it without a handshake. ---
	hopSock, err := net.DialUDP("udp", nil, mustUDPAddr(t, opB.ClientAddr()))
	if err != nil {
		t.Fatalf("hop socket: %v", err)
	}
	defer hopSock.Close()

	// Reader on B for the delivered packet.
	recv := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 65535)
		n, err := connB.ReadPacket(buf)
		if err == nil && n > 0 {
			recv <- append([]byte(nil), buf[:n]...)
		}
	}()

	// Seal an A->B IP packet under A's session and fire it at opB.
	ipPkt := makeIPv4Packet(scA.IP, scB.IP, []byte("hopped-hello"))
	frame, err := datacom.Seal(dialedA.Session, datacom.TagOf(scA.SessionID), ipPkt)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := hopSock.Write(frame); err != nil {
		t.Fatalf("hop write: %v", err)
	}

	select {
	case got := <-recv:
		dst := netip.AddrFrom4([4]byte{got[16], got[17], got[18], got[19]})
		if dst != scB.IP {
			t.Fatalf("delivered to wrong dst %s want %s", dst, scB.IP)
		}
		t.Logf("hopped frame A@opA -> B@opB delivered (%d bytes), no re-handshake", len(got))
	case <-time.After(3 * time.Second):
		t.Fatal("hopped frame not delivered to B within 3s")
	}

	// The migration must have recorded opB as A's new access point.
	waitFor(t, 3*time.Second, func() bool {
		k, ok := node1.SessionByTag(datacom.TagOf(scA.SessionID))
		return ok && k.LastOperator == uuidB
	})
	t.Log("SessionMigrate committed: A's access point is now opB")
}

// --------------- helpers ---------------

func waitLeader(t *testing.T, nodes ...*consensus.Node) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			if n.IsLeader() {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no leader elected")
}

func mustPropose(t *testing.T, n *consensus.Node, c *consensus.Command) {
	t.Helper()
	if err := n.Propose(c, 2*time.Second); err != nil {
		t.Fatalf("propose %v: %v", c.Kind, err)
	}
}

func mustStart(t *testing.T, op *operator.Operator) {
	t.Helper()
	if err := op.Start(); err != nil {
		t.Fatalf("operator start: %v", err)
	}
}

func mkHopOperator(t *testing.T, uuid [16]byte, priv noise.PrivateKey, vni protocol.VNI_Ty, pubs ...noise.PublicKey) *operator.Operator {
	t.Helper()
	auth := make(map[noise.PublicKey]struct{}, len(pubs))
	for _, p := range pubs {
		auth[p] = struct{}{}
	}
	op, err := operator.New(&operator.StaticOperatorConfig{
		UUID:            &uuid,
		StaticPriv:      priv,
		ClientListeners: []operator.ListenerSpec{{Transport: "udp", Addr: "127.0.0.1:0"}},
		OpListenAddr:    "127.0.0.1:0",
		Network: map[protocol.VNI_Ty]operator.StaticOperatorVNetConfig{
			vni: {VNI: vni, CIDR: "10.0.200.0/24", AuthorizedKeys: auth},
		},
		LogLevel: logrus.ErrorLevel,
	})
	if err != nil {
		t.Fatalf("operator.New: %v", err)
	}
	return op
}

func mustUDPAddr(t *testing.T, s string) *net.UDPAddr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		t.Fatalf("resolve %q: %v", s, err)
	}
	return a
}

// waitFor polls cond until it returns true or the timeout elapses.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}
