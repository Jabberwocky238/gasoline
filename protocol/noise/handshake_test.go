package noise

import (
	"bytes"
	"testing"
)

func ts() []byte { return bytes.Repeat([]byte{0x42}, TimestampSize) }

// TestHandshakeSucceedsAndKeysMatch runs a full IK exchange and asserts the
// two sides derive mirrored transport keys (initiator.Send == responder.Recv).
func TestHandshakeSucceedsAndKeysMatch(t *testing.T) {
	cPriv, cPub, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sPriv, sPub, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	initr := NewInitiator(cPriv, cPub, sPub)
	respr := NewResponder(sPriv, sPub)

	msg1, err := initr.WriteInitiation(ts())
	if err != nil {
		t.Fatalf("write initiation: %v", err)
	}
	if len(msg1) != InitiationSize {
		t.Fatalf("msg1 len = %d, want %d", len(msg1), InitiationSize)
	}

	gotStatic, gotTS, err := respr.ReadInitiation(msg1)
	if err != nil {
		t.Fatalf("read initiation: %v", err)
	}
	if gotStatic != cPub {
		t.Fatal("responder recovered wrong client static key")
	}
	if !bytes.Equal(gotTS, ts()) {
		t.Fatalf("timestamp mismatch: %x", gotTS)
	}

	msg2, rKeys, err := respr.WriteResponse()
	if err != nil {
		t.Fatalf("write response: %v", err)
	}
	if len(msg2) != ResponseSize {
		t.Fatalf("msg2 len = %d, want %d", len(msg2), ResponseSize)
	}

	iKeys, err := initr.ReadResponse(msg2)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	// Mirrored keys: what one sends, the other receives.
	if iKeys.Send != rKeys.Recv {
		t.Fatal("initiator.Send != responder.Recv")
	}
	if iKeys.Recv != rKeys.Send {
		t.Fatal("initiator.Recv != responder.Send")
	}
}

// TestWrongResponderKeyFails: a client that targets the wrong server static key
// must not authenticate (the responder cannot decrypt msg1).
func TestWrongResponderKeyFails(t *testing.T) {
	cPriv, cPub, _ := GenerateKey()
	sPriv, sPub, _ := GenerateKey()
	_, wrongPub, _ := GenerateKey() // client aims here by mistake

	initr := NewInitiator(cPriv, cPub, wrongPub)
	respr := NewResponder(sPriv, sPub)

	msg1, err := initr.WriteInitiation(ts())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := respr.ReadInitiation(msg1); err != ErrDecrypt {
		t.Fatalf("expected ErrDecrypt, got %v", err)
	}
}

// TestTamperedInitiationFails: flipping any byte of msg1 breaks AEAD.
func TestTamperedInitiationFails(t *testing.T) {
	cPriv, cPub, _ := GenerateKey()
	sPriv, sPub, _ := GenerateKey()

	msg1, err := NewInitiator(cPriv, cPub, sPub).WriteInitiation(ts())
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte inside the encrypted-static region (after the 32-byte ephemeral).
	msg1[KeySize+1] ^= 0xFF

	if _, _, err := NewResponder(sPriv, sPub).ReadInitiation(msg1); err != ErrDecrypt {
		t.Fatalf("expected ErrDecrypt on tamper, got %v", err)
	}
}

// TestTamperedResponseFails: a corrupted msg2 must not yield keys.
func TestTamperedResponseFails(t *testing.T) {
	cPriv, cPub, _ := GenerateKey()
	sPriv, sPub, _ := GenerateKey()

	initr := NewInitiator(cPriv, cPub, sPub)
	respr := NewResponder(sPriv, sPub)

	msg1, _ := initr.WriteInitiation(ts())
	if _, _, err := respr.ReadInitiation(msg1); err != nil {
		t.Fatal(err)
	}
	msg2, _, err := respr.WriteResponse()
	if err != nil {
		t.Fatal(err)
	}
	msg2[KeySize+1] ^= 0xFF // corrupt the AEAD tag region

	if _, err := initr.ReadResponse(msg2); err != ErrDecrypt {
		t.Fatalf("expected ErrDecrypt, got %v", err)
	}
}

// TestPublicKeyDerivationStable: a private key always derives the same public.
func TestPublicKeyDerivationStable(t *testing.T) {
	priv, pub, _ := GenerateKey()
	if priv.Public() != pub {
		t.Fatal("Public() not stable")
	}
}
