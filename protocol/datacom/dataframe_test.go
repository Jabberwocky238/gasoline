package datacom

import (
	"bytes"
	"testing"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/noise"
)

// pair builds two sessions sharing keys as a CE<->PE pair would: the client's
// Send is the PE's Recv (C2SKey) and vice versa (S2CKey).
func pair(t *testing.T) (client, pe *noise.Session) {
	t.Helper()
	var c2s, s2c [32]byte
	for i := range c2s {
		c2s[i], s2c[i] = byte(i+1), byte(0xff-i)
	}
	// Client: Send=c2s (encrypts client->PE), Recv=s2c.
	client, err := noise.NewSession(noise.TransportKeys{Send: c2s, Recv: s2c}, true)
	if err != nil {
		t.Fatal(err)
	}
	// PE reconstructs from Raft-stored keys: seals PE->client (s2c), opens
	// client->PE (c2s).
	pe, err = noise.SessionFromKeys(s2c, c2s)
	if err != nil {
		t.Fatal(err)
	}
	return client, pe
}

func TestSealOpenRoundTrip(t *testing.T) {
	client, pe := pair(t)
	sid := protocol.NewSessionID()
	tag := TagOf(sid)
	ipPkt := []byte{0x45, 0, 0, 20, 1, 2, 3, 4} // fake IPv4 header start

	frame, err := Seal(client, tag, ipPkt)
	if err != nil {
		t.Fatal(err)
	}

	gotTag, ctr, ct, err := ParseHeader(frame)
	if err != nil {
		t.Fatal(err)
	}
	if gotTag != tag {
		t.Fatalf("tag mismatch: %x != %x", gotTag, tag)
	}
	if ctr != 0 {
		t.Fatalf("first counter should be 0, got %d", ctr)
	}

	pt, err := Open(pe, ctr, ct, true)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(pt, ipPkt) {
		t.Fatalf("plaintext mismatch: %x != %x", pt, ipPkt)
	}
}

func TestForgedFrameRejected(t *testing.T) {
	client, pe := pair(t)
	tag := TagOf(protocol.NewSessionID())
	frame, err := Seal(client, tag, []byte("hello world"))
	if err != nil {
		t.Fatal(err)
	}
	// Flip one ciphertext byte.
	frame[HeaderSize+1] ^= 0x01
	_, ctr, ct, _ := ParseHeader(frame)
	if _, err := Open(pe, ctr, ct, true); err == nil {
		t.Fatal("expected AEAD open to reject a tampered frame")
	}
}

func TestReplayRejected(t *testing.T) {
	client, pe := pair(t)
	tag := TagOf(protocol.NewSessionID())
	frame, _ := Seal(client, tag, []byte("packet"))
	_, ctr, ct, _ := ParseHeader(frame)
	if _, err := Open(pe, ctr, ct, true); err != nil {
		t.Fatalf("first open: %v", err)
	}
	// Same counter again → replay window rejects it.
	if _, err := Open(pe, ctr, ct, true); err == nil {
		t.Fatal("expected replay of the same counter to be rejected")
	}
}

func TestShortFrame(t *testing.T) {
	if _, _, _, err := ParseHeader(make([]byte, HeaderSize-1)); err == nil {
		t.Fatal("expected short frame error")
	}
}
