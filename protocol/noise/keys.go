// Package noise implements the Noise_IK handshake and the transport-cipher
// state used by the gasoline data plane, following the WireGuard construction
// (Curve25519 / BLAKE2s / ChaCha20-Poly1305).
//
// Identity is the static key pair: a peer IS its static public key. The
// handshake both authenticates (only the holder of the matching private key
// can complete it) and derives the pair of transport keys used to encrypt
// data-plane frames. No signatures, no PKI — see PRD §3 / §7.
package noise

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/curve25519"
)

// KeySize is the length of every X25519 key and DH output.
const KeySize = 32

// PrivateKey / PublicKey are raw 32-byte X25519 keys.
type (
	PrivateKey [KeySize]byte
	PublicKey  [KeySize]byte
)

// GenerateKey returns a fresh X25519 key pair.
func GenerateKey() (PrivateKey, PublicKey, error) {
	var priv PrivateKey
	if _, err := rand.Read(priv[:]); err != nil {
		return PrivateKey{}, PublicKey{}, err
	}
	clamp(&priv)
	pub := priv.Public()
	return priv, pub, nil
}

// Public derives the public key from a private key.
func (p PrivateKey) Public() PublicKey {
	var pub PublicKey
	priv := p
	clamp(&priv)
	curve25519.ScalarBaseMult((*[32]byte)(&pub), (*[32]byte)(&priv))
	return pub
}

// dh computes the X25519 shared secret DH(priv, peer). Returns an error if the
// result is all-zero (a low-order point attack), matching x/crypto policy.
func dh(priv PrivateKey, peer PublicKey) ([]byte, error) {
	out, err := curve25519.X25519(priv[:], peer[:])
	if err != nil {
		return nil, err
	}
	return out, nil
}

// clamp applies the standard X25519 private-scalar clamping.
func clamp(p *PrivateKey) {
	p[0] &= 248
	p[31] &= 127
	p[31] |= 64
}

// IsZero reports whether the public key is all zero (unset).
func (p PublicKey) IsZero() bool {
	for _, b := range p {
		if b != 0 {
			return false
		}
	}
	return true
}

var errBadKey = errors.New("noise: invalid key length")

// PublicKeyFromSlice copies exactly KeySize bytes into a PublicKey.
func PublicKeyFromSlice(b []byte) (PublicKey, error) {
	var p PublicKey
	if len(b) != KeySize {
		return p, errBadKey
	}
	copy(p[:], b)
	return p, nil
}

// PrivateKeyFromSlice copies exactly KeySize bytes into a PrivateKey.
func PrivateKeyFromSlice(b []byte) (PrivateKey, error) {
	var p PrivateKey
	if len(b) != KeySize {
		return p, errBadKey
	}
	copy(p[:], b)
	return p, nil
}
