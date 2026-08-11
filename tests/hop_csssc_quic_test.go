package tests

import (
	"testing"
	"time"

	"github.com/jabberwocky238/gasoline/protocol/datacom"
	"github.com/jabberwocky238/gasoline/transport"
)

// TestHopCSSSC_QUIC is the client-driven multi-server hop over QUIC: client A
// handshakes with opA over QUIC, then hops to opB by dialing a FRESH QUIC
// connection (PRD §5.4.4 — QUIC hops by re-connecting) and sending its data
// frames there. opB, which never handshook A, recognizes the data frame on the
// new connection's first stream and serves it via its demux (keys from Raft),
// delivering to local B with no re-handshake.
func TestHopCSSSC_QUIC(t *testing.T) {
	h := setupHopMeshQUIC(t)
	defer h.close()

	hopConn, ok := h.dialedA.Conn.(transport.HoppingConn)
	if !ok {
		t.Fatal("A's QUIC conn is not hopping-capable")
	}

	waitFor(t, 3*time.Second, func() bool {
		_, ok := h.node.SessionByTag(datacom.TagOf(h.scA.SessionID))
		return ok
	})

	recv := make(chan []byte, 8)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := h.connB.ReadPacket(buf)
			if err != nil {
				return
			}
			if n > 0 {
				recv <- append([]byte(nil), buf[:n]...)
			}
		}
	}()

	tag := datacom.TagOf(h.scA.SessionID)
	sendTo := func(payload string) error {
		pkt := makeIPv4Packet(h.scA.IP, h.scB.IP, []byte(payload))
		frame, err := datacom.Seal(h.dialedA.Session, tag, pkt)
		if err != nil {
			return err
		}
		return h.dialedA.Conn.WritePacket(frame)
	}

	// 1) BASELINE via opA: opA forwards to B over the underlay (route learned
	// from Raft route-sync).
	deliveredViaA := false
	for i := 0; i < 20 && !deliveredViaA; i++ {
		if err := sendTo("via-opA"); err != nil {
			t.Fatalf("send via opA: %v", err)
		}
		select {
		case got := <-recv:
			if dstOf(got) == h.scB.IP {
				deliveredViaA = true
			}
		case <-time.After(300 * time.Millisecond):
		}
	}
	if !deliveredViaA {
		t.Fatal("baseline via opA: B never received")
	}
	t.Log("baseline via opA delivered (QUIC)")

	// 2) HOP: dial a fresh QUIC connection to opB and send there.
	if err := hopConn.SetHopDest(h.opB.ClientAddr()); err != nil {
		t.Fatalf("hop-dial opB: %v", err)
	}
	t.Logf("A re-dialed a QUIC connection to opB (%s)", h.opB.ClientAddr())

	deliveredViaB := false
	for i := 0; i < 20 && !deliveredViaB; i++ {
		if err := sendTo("via-opB"); err != nil {
			t.Fatalf("send via opB: %v", err)
		}
		select {
		case got := <-recv:
			if dstOf(got) == h.scB.IP {
				deliveredViaB = true
			}
		case <-time.After(300 * time.Millisecond):
		}
	}
	if !deliveredViaB {
		t.Fatal("after QUIC hop to opB: B never received")
	}
	t.Log("after QUIC hop to opB delivered (served by opB demux on a fresh connection)")

	waitFor(t, 3*time.Second, func() bool {
		k, ok := h.node.SessionByTag(tag)
		return ok && k.LastOperator == [16]byte{0xB0}
	})
	t.Log("QUIC CSSSC hop: A handshook@opA, re-dialed→opB, traffic continued, migrate committed")
}

// setupHopMeshQUIC is setupHopMesh over the QUIC transport.
func setupHopMeshQUIC(t *testing.T) *hopMesh {
	t.Helper()
	return setupHopMeshTransport(t, "quic")
}
