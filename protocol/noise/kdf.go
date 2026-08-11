package noise

import (
	"crypto/hmac"
	"hash"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

// Protocol constants. These strings are hashed into the handshake so that two
// deployments with different construction/identifier strings never
// interoperate (domain separation).
const (
	noiseConstruction  = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
	gasolineIdentifier = "gasoline-noise-v1"
)

// hashSize is BLAKE2s-256 output; also the chaining-key / hash length.
const hashSize = blake2s.Size

// newBlake2s returns a fresh unkeyed BLAKE2s-256 hash.
func newBlake2s() (hash.Hash, error) { return blake2s.New256(nil) }

// mixHash returns HASH(prev || data).
func mixHash(prev [hashSize]byte, data []byte) [hashSize]byte {
	h, _ := blake2s.New256(nil)
	h.Write(prev[:])
	h.Write(data)
	var out [hashSize]byte
	copy(out[:], h.Sum(nil))
	return out
}

// hmac1 = HMAC-BLAKE2s(key, in0).
func hmac1(key, in0 []byte) [hashSize]byte {
	mac := hmac.New(func() hash.Hash { h, _ := blake2s.New256(nil); return h }, key)
	mac.Write(in0)
	var out [hashSize]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// hmac2 = HMAC-BLAKE2s(key, in0 || in1).
func hmac2(key, in0, in1 []byte) [hashSize]byte {
	mac := hmac.New(func() hash.Hash { h, _ := blake2s.New256(nil); return h }, key)
	mac.Write(in0)
	mac.Write(in1)
	var out [hashSize]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// kdf1 derives one key from (chainingKey, input), per the WireGuard KDF.
func kdf1(chainingKey [hashSize]byte, input []byte) [hashSize]byte {
	t0 := hmac1(chainingKey[:], input)
	t1 := hmac1(t0[:], []byte{0x1})
	return t1
}

// kdf2 derives two keys from (chainingKey, input).
func kdf2(chainingKey [hashSize]byte, input []byte) (t1, t2 [hashSize]byte) {
	t0 := hmac1(chainingKey[:], input)
	t1 = hmac1(t0[:], []byte{0x1})
	t2 = hmac2(t0[:], t1[:], []byte{0x2})
	return
}

// aeadKey adapts a 32-byte key to a ChaCha20-Poly1305 AEAD.
func aeadKey(key [hashSize]byte) (interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	NonceSize() int
	Overhead() int
}, error) {
	return chacha20poly1305.New(key[:])
}

// nonce constructs the 12-byte ChaCha20-Poly1305 nonce from a 64-bit counter,
// little-endian in the last 8 bytes (WireGuard layout).
func nonce(counter uint64) [chacha20poly1305.NonceSize]byte {
	var n [chacha20poly1305.NonceSize]byte
	n[4] = byte(counter)
	n[5] = byte(counter >> 8)
	n[6] = byte(counter >> 16)
	n[7] = byte(counter >> 24)
	n[8] = byte(counter >> 32)
	n[9] = byte(counter >> 40)
	n[10] = byte(counter >> 48)
	n[11] = byte(counter >> 56)
	return n
}
