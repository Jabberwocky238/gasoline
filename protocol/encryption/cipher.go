package encryption

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	HeaderSize = 8                          // [counter:8] prepended to each message
	TagSize    = chacha20poly1305.Overhead  // 16, Poly1305 tag
	Overhead   = HeaderSize + TagSize       // total overhead per encrypted message
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

// Seal encrypts plaintext into dst in-place.
//
// dst must have capacity for at least HeaderSize + len(plaintext) + TagSize bytes.
// Returns the sub-slice of dst containing the full encrypted message:
//
//	[counter:8][ciphertext + poly1305_tag]
//
// If dst is nil or too small, a new buffer is allocated (fallback).
func (cs *CipherState) Seal(dst, plaintext []byte) []byte {
	counter := cs.nonce.Add(1) - 1
	needed := HeaderSize + len(plaintext) + TagSize

	if cap(dst) < needed {
		dst = make([]byte, HeaderSize, needed)
	} else {
		dst = dst[:HeaderSize]
	}

	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	binary.LittleEndian.PutUint64(dst[:HeaderSize], counter)

	// Seal appends ciphertext+tag after dst[HeaderSize:]
	return cs.aead.Seal(dst, nonce[:], plaintext, nil)
}

// Open decrypts message in-place into dst.
//
// message format: [counter:8][ciphertext + poly1305_tag]
// dst must have capacity for at least len(message) - Overhead bytes.
// Returns the sub-slice of dst containing the plaintext.
//
// If dst is nil, a new buffer is allocated (fallback).
func (cs *CipherState) Open(dst, message []byte) ([]byte, error) {
	if len(message) < Overhead {
		return nil, fmt.Errorf("message too short: %d bytes", len(message))
	}
	counter := binary.LittleEndian.Uint64(message[:HeaderSize])

	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)

	plaintext, err := cs.aead.Open(dst[:0], nonce[:], message[HeaderSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("AEAD open failed: %w", err)
	}
	return plaintext, nil
}
