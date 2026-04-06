package protocol

import (
	"bytes"
	"testing"
)

func TestCipherStateSealOpen(t *testing.T) {
	var key [32]byte
	copy(key[:], []byte("test-key-32-bytes-long-padding!!"))

	send, err := NewCipherState(key)
	if err != nil {
		t.Fatalf("NewCipherState: %v", err)
	}
	recv, err := NewCipherState(key)
	if err != nil {
		t.Fatalf("NewCipherState: %v", err)
	}

	plaintext := []byte("hello gasoline")
	encrypted := send.Seal(plaintext)

	if bytes.Equal(encrypted[AEADHeaderSize:], plaintext) {
		t.Fatal("encrypted should differ from plaintext")
	}

	decrypted, err := recv.Open(encrypted)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestCipherStateNonceIncrement(t *testing.T) {
	var key [32]byte
	copy(key[:], []byte("test-key-32-bytes-long-padding!!"))

	cs, _ := NewCipherState(key)

	msg1 := cs.Seal([]byte("a"))
	msg2 := cs.Seal([]byte("b"))

	// Different nonces should produce different ciphertexts
	if bytes.Equal(msg1, msg2) {
		t.Error("two messages with different nonces should differ")
	}
}

func TestCipherStateTamperedMessage(t *testing.T) {
	var key [32]byte
	copy(key[:], []byte("test-key-32-bytes-long-padding!!"))

	cs, _ := NewCipherState(key)
	encrypted := cs.Seal([]byte("secret data"))

	// Tamper with ciphertext
	encrypted[AEADHeaderSize+5] ^= 0xFF

	recv, _ := NewCipherState(key)
	_, err := recv.Open(encrypted)
	if err == nil {
		t.Fatal("expected error for tampered message")
	}
}

func TestDeriveSessionKeypairSymmetry(t *testing.T) {
	clientPriv, _ := NewPrivateKey()
	serverPriv, _ := NewPrivateKey()
	clientPub := clientPriv.PublicKey()
	serverPub := serverPriv.PublicKey()

	// Client derives with (clientPriv, serverPub, initiator=true)
	clientKP, err := DeriveSessionKeypair(clientPriv, serverPub, true)
	if err != nil {
		t.Fatalf("client DeriveSessionKeypair: %v", err)
	}

	// Server derives with (serverPriv, clientPub, initiator=false)
	serverKP, err := DeriveSessionKeypair(serverPriv, clientPub, false)
	if err != nil {
		t.Fatalf("server DeriveSessionKeypair: %v", err)
	}

	// Client encrypts, server decrypts
	plaintext := []byte("test message from client to server")
	encrypted := clientKP.Send.Seal(plaintext)

	decrypted, err := serverKP.Receive.Open(encrypted)
	if err != nil {
		t.Fatalf("server decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("client→server decryption mismatch")
	}

	// Server encrypts, client decrypts
	replyText := []byte("reply from server to client")
	replyEncrypted := serverKP.Send.Seal(replyText)

	replyDecrypted, err := clientKP.Receive.Open(replyEncrypted)
	if err != nil {
		t.Fatalf("client decrypt: %v", err)
	}
	if !bytes.Equal(replyDecrypted, replyText) {
		t.Error("server→client decryption mismatch")
	}
}

func TestDeriveSessionKeypairCrossDecryptFails(t *testing.T) {
	clientPriv, _ := NewPrivateKey()
	serverPriv, _ := NewPrivateKey()
	serverPub := serverPriv.PublicKey()

	clientKP, _ := DeriveSessionKeypair(clientPriv, serverPub, true)

	// Try to decrypt with the wrong key direction
	plaintext := []byte("should not decrypt")
	encrypted := clientKP.Send.Seal(plaintext)

	// Using Send cipher (same key) to Open should work (same key both sides)
	// But using a completely different key should fail
	otherPriv, _ := NewPrivateKey()
	otherKP, _ := DeriveSessionKeypair(otherPriv, serverPub, false)

	_, err := otherKP.Receive.Open(encrypted)
	if err == nil {
		t.Error("expected decryption failure with wrong key")
	}
}

func TestSessionConfigMarshalUnmarshal(t *testing.T) {
	priv, _ := NewPrivateKey()
	pub := priv.PublicKey()

	original := &SessionConfig{
		ClientPrivateKey: priv,
		ServerPublicKey:  pub,
	}
	// Set IPPrefix
	import_netip := func() {
		// use netip inside test
	}
	_ = import_netip

	data := original.Marshal()
	if len(data) != sessionConfigSize {
		t.Fatalf("marshal size: got %d, want %d", len(data), sessionConfigSize)
	}

	var decoded SessionConfig
	if err := decoded.Unmarshal(data); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.ClientPrivateKey != original.ClientPrivateKey {
		t.Error("ClientPrivateKey mismatch")
	}
	if decoded.ServerPublicKey != original.ServerPublicKey {
		t.Error("ServerPublicKey mismatch")
	}
}
