package encryption

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

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
// localPrivate:  our Curve25519 private key (32 bytes)
// remotePublic:  peer's Curve25519 public key (32 bytes)
// initiator:     true for client, false for server
//
// Both sides derive the same shared secret via ECDH, then use HKDF-SHA256
// to produce two 32-byte symmetric keys. The initiator and responder
// swap send/recv so that one side's send key == the other side's recv key.
func DeriveSessionKeypair(localPrivate PrivateKey, remotePublic PublicKey, initiator bool) (*SessionKeypair, error) {
	shared, err := curve25519.X25519(localPrivate[:], remotePublic[:])
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

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
