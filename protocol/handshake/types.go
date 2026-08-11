package handshake

const (
	// HandshakeVersion is v2: Noise_IK identity binding. There is no v1
	// compatibility — the old HMAC/challenge model was removed wholesale.
	HandshakeVersion = 0x02
)

type HandshakeCode uint32

const (
	HandshakeOK          HandshakeCode = 0x00
	HandshakeUnknownFail HandshakeCode = 0x01
	HandshakeAuthFail    HandshakeCode = 0x02 // decrypt failed / CID mismatch / unauthorized key
	HandshakeQOS         HandshakeCode = 0x03
	HandshakeNoRoute     HandshakeCode = 0x04
	HandshakeConflict    HandshakeCode = 0x05 // key already has a live session elsewhere (PRD §8)
)

type HandshakeCryptoSuite uint16

const (
	// CryptoSuite_NoiseIK is the only supported suite: Noise_IK over
	// Curve25519 / ChaCha20-Poly1305 / BLAKE2s.
	CryptoSuite_NoiseIK HandshakeCryptoSuite = 0x0001
)
