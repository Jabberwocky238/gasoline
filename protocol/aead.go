package protocol

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// AEADHeaderSize: [counter:8] prepended to each encrypted message.
	AEADHeaderSize = 8
	// AEADTagSize: Poly1305 authentication tag.
	AEADTagSize = chacha20poly1305.Overhead // 16
)

// CipherState holds one direction's AEAD state (send OR receive).
type CipherState struct {
	aead  cipher.AEAD
	nonce atomic.Uint64
}

// NewCipherState creates a CipherState from a 32-byte ChaCha20-Poly1305 key.
func NewCipherState(key [32]byte) (*CipherState, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return &CipherState{aead: aead}, nil
}

// Seal encrypts plaintext and returns: [counter:8][ciphertext+tag].
func (cs *CipherState) Seal(plaintext []byte) []byte {
	counter := cs.nonce.Add(1) - 1

	var nonce [chacha20poly1305.NonceSize]byte // 12 bytes
	binary.LittleEndian.PutUint64(nonce[4:], counter)

	out := make([]byte, AEADHeaderSize, AEADHeaderSize+len(plaintext)+AEADTagSize)
	binary.LittleEndian.PutUint64(out[:AEADHeaderSize], counter)
	out = cs.aead.Seal(out, nonce[:], plaintext, nil)
	return out
}

// Open decrypts a message produced by Seal: [counter:8][ciphertext+tag].
func (cs *CipherState) Open(message []byte) ([]byte, error) {
	if len(message) < AEADHeaderSize+AEADTagSize {
		return nil, fmt.Errorf("message too short: %d bytes", len(message))
	}
	counter := binary.LittleEndian.Uint64(message[:AEADHeaderSize])

	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)

	plaintext, err := cs.aead.Open(nil, nonce[:], message[AEADHeaderSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("AEAD open failed: %w", err)
	}
	return plaintext, nil
}

// SessionKeypair holds send and receive cipher states for a session.
type SessionKeypair struct {
	Send    *CipherState
	Receive *CipherState
}

// NewSessionKeypair creates a keypair from two 32-byte symmetric keys.
func NewSessionKeypair(sendKey, recvKey [32]byte) (*SessionKeypair, error) {
	send, err := NewCipherState(sendKey)
	if err != nil {
		return nil, err
	}
	recv, err := NewCipherState(recvKey)
	if err != nil {
		return nil, err
	}
	return &SessionKeypair{Send: send, Receive: recv}, nil
}

// DeriveSessionKeypair performs ECDH and derives a SessionKeypair.
//
// localPrivate:  our Curve25519 private key
// remotePubic:   peer's Curve25519 public key
// initiator:     true for client, false for server
//
// Both sides derive the same shared secret via ECDH, then use HKDF-SHA256
// to produce two 32-byte symmetric keys. The initiator and responder
// swap send/recv so that one side's send key == the other side's recv key.
func DeriveSessionKeypair(localPrivate PrivateKey, remotePublic PublicKey, initiator bool) (*SessionKeypair, error) {
	// ECDH: shared = curve25519(local_private, remote_public)
	shared, err := curve25519.X25519(localPrivate[:], remotePublic[:])
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// HKDF-SHA256: derive 64 bytes (two 32-byte keys)
	hkdfReader := hkdf.New(sha256.New, shared, nil, []byte("gasoline-session-keys"))
	var key1, key2 [32]byte
	if _, err := io.ReadFull(hkdfReader, key1[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(hkdfReader, key2[:]); err != nil {
		return nil, err
	}

	if initiator {
		return NewSessionKeypair(key1, key2)
	}
	return NewSessionKeypair(key2, key1)
}
