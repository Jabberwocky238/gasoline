package tests

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/jabberwocky238/gasoline/cmd/operator/device/consensus"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/datacom"
	"github.com/jabberwocky238/gasoline/protocol/noise"
	"github.com/jabberwocky238/gasoline/transport"
	"github.com/jabberwocky238/gasoline/transport/udp"
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
	opA := mkHopOperator(t, "udp", uuidA, serverPriv, vni, pubA, pubB)
	opA.AttachConsensus(node)
	mustStart(t, opA)
	defer opA.Close()
	opB := mkHopOperator(t, "udp", uuidB, serverPriv, vni, pubA, pubB)
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

// TestG4_ForgedFrameDropped proves an attacker who knows a live SessionTag (it
// travels in the clear) but not the session keys cannot inject traffic: the
// demux's AEAD open fails and the frame is dropped, never forwarded (PRD §6.4).
func TestG4_ForgedFrameDropped(t *testing.T) {
	h := setupHopMesh(t)
	defer h.close()

	// Wait until opB's FSM has A's session.
	waitFor(t, 3*time.Second, func() bool {
		_, ok := h.node.SessionByTag(datacom.TagOf(h.scA.SessionID))
		return ok
	})

	// B watches for ANY delivered packet.
	recv := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 65535)
		if n, err := h.connB.ReadPacket(buf); err == nil && n > 0 {
			recv <- struct{}{}
		}
	}()

	// Forge a frame: correct SessionTag for A, but garbage ciphertext (attacker
	// lacks the keys). Fire it at opB from a fresh socket.
	sock, err := net.DialUDP("udp", nil, mustUDPAddr(t, h.opB.ClientAddr()))
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer sock.Close()

	tag := datacom.TagOf(h.scA.SessionID)
	forged := make([]byte, datacom.HeaderSize+32)
	copy(forged, tag[:])
	// counter=0, then 32 bytes of zero "ciphertext" that cannot authenticate.
	if _, err := sock.Write(forged); err != nil {
		t.Fatalf("write forged: %v", err)
	}

	select {
	case <-recv:
		t.Fatal("forged frame was delivered — AEAD did not reject it")
	case <-time.After(1 * time.Second):
		t.Log("forged frame dropped (AEAD open failed), nothing delivered")
	}
}

// TestG4_SurvivesOperatorKill proves session continuity across operator loss
// (PRD §9.4): A handshakes with opA, then opA is killed; A's frames sent to opB
// are still served (keys live in Raft), delivered to B, no re-handshake.
func TestG4_SurvivesOperatorKill(t *testing.T) {
	h := setupHopMesh(t)
	defer h.close()

	waitFor(t, 3*time.Second, func() bool {
		_, ok := h.node.SessionByTag(datacom.TagOf(h.scA.SessionID))
		return ok
	})

	// Kill the operator A handshook with.
	_ = h.opA.Close()
	t.Log("opA (A's handshake operator) killed")

	recv := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 65535)
		if n, err := h.connB.ReadPacket(buf); err == nil && n > 0 {
			recv <- append([]byte(nil), buf[:n]...)
		}
	}()

	sock, err := net.DialUDP("udp", nil, mustUDPAddr(t, h.opB.ClientAddr()))
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer sock.Close()

	ipPkt := makeIPv4Packet(h.scA.IP, h.scB.IP, []byte("post-kill"))
	frame, err := datacom.Seal(h.dialedA.Session, datacom.TagOf(h.scA.SessionID), ipPkt)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := sock.Write(frame); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case <-recv:
		t.Log("A's frame delivered to B via opB after opA was killed — session survived")
	case <-time.After(3 * time.Second):
		t.Fatal("frame not delivered after opA kill")
	}
}
