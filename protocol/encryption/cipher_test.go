package encryption

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
	encrypted := send.Seal(nil, plaintext)

	if bytes.Equal(encrypted[HeaderSize:], plaintext) {
		t.Fatal("encrypted should differ from plaintext")
	}

	decrypted, err := recv.Open(nil, encrypted)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestCipherStateSealOpenInPlace(t *testing.T) {
	var key [32]byte
	copy(key[:], []byte("test-key-32-bytes-long-padding!!"))

	send, _ := NewCipherState(key)
	recv, _ := NewCipherState(key)

	plaintext := []byte("in-place test data 1234567890")

	// Seal into pre-allocated dst
	dst := make([]byte, HeaderSize+len(plaintext)+TagSize)
	encrypted := send.Seal(dst, plaintext)

	// Open into pre-allocated buf
	buf := make([]byte, len(plaintext))
	decrypted, err := recv.Open(buf, encrypted)
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

	msg1 := cs.Seal(nil, []byte("a"))
	msg2 := cs.Seal(nil, []byte("b"))

	if bytes.Equal(msg1, msg2) {
		t.Error("two messages with different nonces should differ")
	}
}

func TestCipherStateTamperedMessage(t *testing.T) {
	var key [32]byte
	copy(key[:], []byte("test-key-32-bytes-long-padding!!"))

	cs, _ := NewCipherState(key)
	encrypted := cs.Seal(nil, []byte("secret data"))

	encrypted[HeaderSize+5] ^= 0xFF

	recv, _ := NewCipherState(key)
	_, err := recv.Open(nil, encrypted)
	if err == nil {
		t.Fatal("expected error for tampered message")
	}
}

func TestDeriveSessionKeypairSymmetry(t *testing.T) {
	clientPriv, _ := NewPrivateKey()
	serverPriv, _ := NewPrivateKey()
	clientPub := clientPriv.PublicKey()
	serverPub := serverPriv.PublicKey()

	clientKP, err := DeriveSessionKeypair(clientPriv, serverPub, true)
	if err != nil {
		t.Fatalf("client DeriveSessionKeypair: %v", err)
	}
	serverKP, err := DeriveSessionKeypair(serverPriv, clientPub, false)
	if err != nil {
		t.Fatalf("server DeriveSessionKeypair: %v", err)
	}

	// Client encrypts, server decrypts
	plaintext := []byte("test message from client to server")
	encrypted := clientKP.Send.Seal(nil, plaintext)

	decrypted, err := serverKP.Receive.Open(nil, encrypted)
	if err != nil {
		t.Fatalf("server decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("client→server decryption mismatch")
	}

	// Server encrypts, client decrypts
	replyText := []byte("reply from server to client")
	replyEncrypted := serverKP.Send.Seal(nil, replyText)

	replyDecrypted, err := clientKP.Receive.Open(nil, replyEncrypted)
	if err != nil {
		t.Fatalf("client decrypt: %v", err)
	}
	if !bytes.Equal(replyDecrypted, replyText) {
		t.Error("server→client decryption mismatch")
	}
}

func TestAEADOverhead1400(t *testing.T) {
	var key [32]byte
	copy(key[:], []byte("test-key-32-bytes-long-padding!!"))

	cs, err := NewCipherState(key)
	if err != nil {
		t.Fatalf("NewCipherState: %v", err)
	}

	plaintext := make([]byte, 1400)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	encrypted := cs.Seal(nil, plaintext)
	expectedLen := HeaderSize + 1400 + TagSize // 8 + 1400 + 16 = 1424

	t.Logf("plaintext:  %d bytes", len(plaintext))
	t.Logf("encrypted:  %d bytes", len(encrypted))
	t.Logf("overhead:   %d bytes (header=%d + tag=%d)", Overhead, HeaderSize, TagSize)

	if len(encrypted) != expectedLen {
		t.Fatalf("encrypted length = %d, want %d", len(encrypted), expectedLen)
	}

	// Verify it can be decrypted back
	recv, _ := NewCipherState(key)
	decrypted, err := recv.Open(nil, encrypted)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(decrypted) != 1400 {
		t.Fatalf("decrypted length = %d, want 1400", len(decrypted))
	}
}

func TestDeriveSessionKeypairCrossDecryptFails(t *testing.T) {
	clientPriv, _ := NewPrivateKey()
	serverPriv, _ := NewPrivateKey()
	serverPub := serverPriv.PublicKey()

	clientKP, _ := DeriveSessionKeypair(clientPriv, serverPub, true)

	plaintext := []byte("should not decrypt")
	encrypted := clientKP.Send.Seal(nil, plaintext)

	otherPriv, _ := NewPrivateKey()
	otherKP, _ := DeriveSessionKeypair(otherPriv, serverPub, false)

	_, err := otherKP.Receive.Open(nil, encrypted)
	if err == nil {
		t.Error("expected decryption failure with wrong key")
	}
}
