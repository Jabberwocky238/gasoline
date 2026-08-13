package noise

import "testing"

// TestHopCounterNoFalseReplay verifies that two operators sealing to one client
// under the same S2CKey (client hopped) don't trigger false replay rejections:
// each operator uses a distinct tag, the client validates per-tag.
func TestHopCounterNoFalseReplay(t *testing.T) {
	var s2c, c2s [32]byte
	for i := range s2c {
		s2c[i], c2s[i] = byte(i+1), byte(0xff-i)
	}

	// client opens with S2CKey (recv), tag doesn't matter for its send.
	client, _ := NewSession(TransportKeys{Send: c2s, Recv: s2c}, true)
	// two operators seal PE->client under S2CKey, distinct tags.
	op1, _ := SessionFromKeys(s2c, c2s, 111)
	op2, _ := SessionFromKeys(s2c, c2s, 222)

	aad := []byte("x")
	// op1 sends 3 frames, client accepts all.
	for i := 0; i < 3; i++ {
		ctr, ct, _ := op1.SealNext([]byte("a"), aad)
		if _, err := client.OpenAt(ctr, ct, aad, true); err != nil {
			t.Fatalf("op1 frame %d rejected: %v", i, err)
		}
	}
	// op2 sends 3 frames (its seq restarts at 0) — MUST NOT be seen as replays.
	for i := 0; i < 3; i++ {
		ctr, ct, _ := op2.SealNext([]byte("b"), aad)
		if _, err := client.OpenAt(ctr, ct, aad, true); err != nil {
			t.Fatalf("op2 frame %d falsely rejected as replay: %v", i, err)
		}
	}
	// a genuine replay from op1 (re-send counter 0) IS rejected.
	ctr0 := uint64(111) << counterSeqBits
	n := nonce(ctr0)
	ct := op1.send.Seal(nil, n[:], []byte("a"), aad)
	if _, err := client.OpenAt(ctr0, ct, aad, true); err == nil {
		t.Fatal("genuine replay of op1 counter 0 was NOT rejected")
	}
}
