package tests

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jabberwocky238/gasoline/protocol/datacom"
	"github.com/jabberwocky238/gasoline/transport"
)

// TestHopCSSSC_UDP is the client-driven multi-server hop over UDP: client A
// handshakes with opA, then repoints its (unconnected) socket at opB via the
// hop path — exactly what the client Hopper does — and its data frames to B
// keep flowing, served by opB's demux with no re-handshake (PRD §5/§6).
func TestHopCSSSC_UDP(t *testing.T) {
	h := setupHopMesh(t)
	defer h.close()

	// A's conn is a hopping-capable UDP conn (unconnected socket).
	hopConn, ok := h.dialedA.Conn.(transport.HoppingConn)
	if !ok {
		t.Fatal("A's UDP conn is not hopping-capable")
	}

	// Wait until opB's FSM has A's session (so the hop can be served).
	waitFor(t, 3*time.Second, func() bool {
		_, ok := h.node.SessionByTag(datacom.TagOf(h.scA.SessionID))
		return ok
	})

	// B reads whatever arrives.
	recv := make(chan []byte, 4)
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
	sendTo := func(payload string) {
		pkt := makeIPv4Packet(h.scA.IP, h.scB.IP, []byte(payload))
		frame, err := datacom.Seal(h.dialedA.Session, tag, pkt)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		if err := h.dialedA.Conn.WritePacket(frame); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	// 1) BASELINE via opA (A's handshake operator). opA decrypts, sees dst = B's
	// IP owned by opB (learned via Raft route-sync), and forwards over the
	// underlay to opB, which delivers to local B. Retried until the route-sync
	// tick has installed opA -> opB for B's prefix.
	deliveredViaA := false
	for i := 0; i < 20 && !deliveredViaA; i++ {
		sendTo("via-opA")
		select {
		case got := <-recv:
			if dstOf(got) == h.scB.IP {
				deliveredViaA = true
			}
		case <-time.After(300 * time.Millisecond):
		}
	}
	if !deliveredViaA {
		t.Fatal("baseline via opA: B never received (cross-operator route not installed)")
	}
	t.Log("baseline via opA delivered (cross-operator route from Raft)")

	// 2) HOP: repoint A's socket at opB's client listener (what the client
	// Hopper does via SetHopDest) and send B-bound frames. opB, which never
	// handshook A, serves them via its demux (keys from Raft), delivering to B.
	if err := hopConn.SetHopDest(h.opB.ClientAddr()); err != nil {
		t.Fatalf("hop to opB: %v", err)
	}
	t.Logf("A hopped to opB (%s)", h.opB.ClientAddr())

	deliveredViaB := false
	for i := 0; i < 20 && !deliveredViaB; i++ {
		sendTo("via-opB")
		select {
		case got := <-recv:
			if dstOf(got) == h.scB.IP {
				deliveredViaB = true
			}
		case <-time.After(300 * time.Millisecond):
		}
	}
	if !deliveredViaB {
		t.Fatal("after hop to opB: B never received")
	}
	t.Log("after hop to opB delivered (served by opB demux, no re-handshake)")

	// 3) Migration recorded opB as A's access point.
	waitFor(t, 3*time.Second, func() bool {
		k, ok := h.node.SessionByTag(tag)
		return ok && k.LastOperator == [16]byte{0xB0}
	})
	t.Log("UDP CSSSC hop: A handshook@opA, hopped→opB, traffic continued, migrate committed")
}

// dstOf extracts the IPv4 dst address from a packet, or the zero Addr.
func dstOf(pkt []byte) netip.Addr {
	if len(pkt) < 20 {
		return netip.Addr{}
	}
	return netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]})
}
