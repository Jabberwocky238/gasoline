package protocol

import (
	"bytes"
	"net/netip"
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
		IPPrefix:         netip.MustParsePrefix("10.0.0.2/24"),
		AllowedRanges: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/24"),
			netip.MustParsePrefix("192.168.1.0/24"),
			netip.MustParsePrefix("172.16.0.0/12"),
		},
	}

	data := original.Marshal()
	expectedSize := configFixedSize + 2 + 3*prefixEntrySize
	if len(data) != expectedSize {
		t.Fatalf("marshal size: got %d, want %d", len(data), expectedSize)
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
	if decoded.IPPrefix != original.IPPrefix {
		t.Errorf("IPPrefix: got %s, want %s", decoded.IPPrefix, original.IPPrefix)
	}
	if len(decoded.AllowedRanges) != 3 {
		t.Fatalf("AllowedRanges count: got %d, want 3", len(decoded.AllowedRanges))
	}
	for i, r := range decoded.AllowedRanges {
		if r != original.AllowedRanges[i] {
			t.Errorf("AllowedRanges[%d]: got %s, want %s", i, r, original.AllowedRanges[i])
		}
	}
}

func TestSessionConfigEmptyRanges(t *testing.T) {
	priv, _ := NewPrivateKey()
	cfg := &SessionConfig{
		ClientPrivateKey: priv,
		ServerPublicKey:  priv.PublicKey(),
		IPPrefix:         netip.MustParsePrefix("10.0.0.5/24"),
	}

	data := cfg.Marshal()
	var decoded SessionConfig
	if err := decoded.Unmarshal(data); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(decoded.AllowedRanges) != 0 {
		t.Errorf("expected 0 ranges, got %d", len(decoded.AllowedRanges))
	}
	if decoded.IPPrefix.String() != "10.0.0.5/24" {
		t.Errorf("IPPrefix: got %s", decoded.IPPrefix)
	}
}
