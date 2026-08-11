package udp

import (
	"testing"

	"github.com/jabberwocky238/gasoline/protocol/noise"
	"github.com/jabberwocky238/gasoline/transport"
)

// TestUnauthorizedKeyRejected: a client whose static key is not in the VNI's
// authorized set must fail the handshake. This is the core admission property
// after removing noauth — no key, no entry.
func TestUnauthorizedKeyRejected(t *testing.T) {
	// Server key pair; authorize NOBODY.
	sPriv, sPub, err := noise.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := NewListener("127.0.0.1:0", testMapper(sPriv, sPub /* no authorized keys */))
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer ln.Close()

	// Accept loop must never yield a session for an unauthorized client.
	accepted := make(chan struct{}, 1)
	go func() {
		if acc, e := ln.Accept(); e == nil && acc.Conn != nil {
			accepted <- struct{}{}
		}
	}()

	cPriv, cPub, err := noise.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	id := transport.ClientIdentity{Priv: cPriv, Pub: cPub, ServerPub: sPub}
	_, err = NewDialer(newTestCfg(), id).Dial(ln.Addr())
	if err == nil {
		t.Fatal("dial succeeded for unauthorized key; want handshake failure")
	}

	select {
	case <-accepted:
		t.Fatal("server accepted a session for an unauthorized key")
	default:
	}
}

// TestWrongServerKeyRejected: a client that dials with the wrong server public
// key cannot complete the Noise handshake (the responder can't decrypt msg1).
func TestWrongServerKeyRejected(t *testing.T) {
	sPriv, sPub, _ := noise.GenerateKey()
	cPriv, cPub, _ := noise.GenerateKey()
	_, wrongServerPub, _ := noise.GenerateKey()

	ln, err := NewListener("127.0.0.1:0", testMapper(sPriv, sPub, cPub))
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer ln.Close()
	go ln.Accept() //nolint: errcheck — must not succeed

	// Client aims at the wrong server key.
	id := transport.ClientIdentity{Priv: cPriv, Pub: cPub, ServerPub: wrongServerPub}
	if _, err := NewDialer(newTestCfg(), id).Dial(ln.Addr()); err == nil {
		t.Fatal("dial succeeded against wrong server key; want failure")
	}
}
