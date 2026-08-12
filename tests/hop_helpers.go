package tests

// Shared harness and helpers for the hop / multi-server tests (hop_g4_test.go,
// hop_csssc_udp_test.go, hop_csssc_quic_test.go). No Test functions live here —
// this file is fixtures only.

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
	"github.com/jabberwocky238/gasoline/transport/quic"
	"github.com/jabberwocky238/gasoline/transport/udp"
	"github.com/sirupsen/logrus"
)

// --------------- shared hop-mesh harness ---------------

type hopMesh struct {
	node    *consensus.Node
	opA     *operator.Operator
	opB     *operator.Operator
	connB   transport.Conn
	dialedA transport.Dialed
	scA     *protocol.SessionContext
	scB     *protocol.SessionContext
}

func (h *hopMesh) close() {
	if h.connB != nil {
		_ = h.connB.Close()
	}
	if h.dialedA.Conn != nil {
		_ = h.dialedA.Conn.Close()
	}
	if h.opB != nil {
		_ = h.opB.Close()
	}
	if h.opA != nil {
		_ = h.opA.Close()
	}
	if h.node != nil {
		_ = h.node.Shutdown()
	}
}

// setupHopMesh stands up the shared two-operator / one-node fixture: A dialed on
// opA, B dialed on opB, underlay wired, both sessions live in the FSM.
func setupHopMesh(t *testing.T) *hopMesh {
	return setupHopMeshTransport(t, "udp")
}

// setupHopMeshTransport is setupHopMesh parametrized by client transport
// ("udp" or "quic"). Both operators listen on tp; A/B dial over tp.
func setupHopMeshTransport(t *testing.T, tp string) *hopMesh {
	t.Helper()
	const vni protocol.VNI_Ty = 200

	privA, pubA, _ := noise.GenerateKey()
	privB, pubB, _ := noise.GenerateKey()
	serverPriv, serverPub, _ := noise.GenerateKey()

	raftAddr := freeUDPAddr(t)
	node, err := consensus.NewNode(consensus.Config{
		LocalID: "op-0", BindAddr: raftAddr, Peers: []consensus.Peer{{ID: "op-0", Addr: raftAddr}}, Bootstrap: true,
	})
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	waitLeader(t, node)

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

	uuidA := [16]byte{0xA0}
	uuidB := [16]byte{0xB0}
	opA := mkHopOperator(t, tp, uuidA, serverPriv, vni, pubA, pubB)
	opA.AttachConsensus(node)
	mustStart(t, opA)
	opB := mkHopOperator(t, tp, uuidB, serverPriv, vni, pubA, pubB)
	opB.AttachConsensus(node)
	mustStart(t, opB)

	apA, _ := netip.ParseAddrPort(opA.DataPlaneAddr())
	apB, _ := netip.ParseAddrPort(opB.DataPlaneAddr())
	opA.AddPeer(uuidB, apB)
	opB.AddPeer(uuidA, apA)

	idA := transport.ClientIdentity{Priv: privA, Pub: pubA, ServerPub: serverPub}
	idB := transport.ClientIdentity{Priv: privB, Pub: pubB, ServerPub: serverPub}

	dialedA, err := newHopDialer(tp, vni, idA).Dial(opA.ClientAddr())
	if err != nil {
		t.Fatalf("A dial: %v", err)
	}
	scA, err := datacom.ClientAssign(dialedA.Conn, dialedA.Session, vni)
	if err != nil {
		t.Fatalf("A assign: %v", err)
	}
	connB, scB := dialAndAssign(t, newHopDialer(tp, vni, idB), opB.ClientAddr(), idB, vni)

	return &hopMesh{node: node, opA: opA, opB: opB, connB: connB, dialedA: dialedA, scA: scA, scB: scB}
}

// newHopDialer builds a client dialer for the given transport.
func newHopDialer(tp string, vni protocol.VNI_Ty, id transport.ClientIdentity) transport.Dialer {
	cfg := protocol.NewPresetSessionConfig(vni)
	switch tp {
	case "quic":
		return quic.NewDialer(cfg, id, quic.InsecureClientTLS())
	default:
		return udp.NewDialer(cfg, id)
	}
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

func mkHopOperator(t *testing.T, tp string, uuid [16]byte, priv noise.PrivateKey, vni protocol.VNI_Ty, pubs ...noise.PublicKey) *operator.Operator {
	t.Helper()
	auth := make(map[noise.PublicKey]struct{}, len(pubs))
	for _, p := range pubs {
		auth[p] = struct{}{}
	}
	op, err := operator.New(&operator.StaticOperatorConfig{
		UUID:            &uuid,
		StaticPriv:      priv,
		ClientListeners: []operator.ListenerSpec{{Transport: tp, Addr: "127.0.0.1:0"}},
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
