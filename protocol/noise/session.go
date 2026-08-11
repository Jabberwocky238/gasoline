package noise

import (
	"crypto/cipher"
	"errors"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Rekey / reject thresholds, mirrored from WireGuard (constants.go). A session
// must rekey before RekeyAfter and is unusable past RejectAfter.
// Left untyped, as upstream writes them: Go evaluates untyped constant
// expressions in arbitrary precision, so the intermediate 1<<64 is fine and
// only the final value has to fit. Writing uint64(1) << 64 instead makes the
// intermediate a typed uint64 and fails to compile with an overflow.
const (
	RekeyAfterMessages  = (1 << 60)
	RejectAfterMessages = (1 << 64) - (1 << 13) - 1
	RekeyAfterTime      = 120 * time.Second
	RejectAfterTime     = 180 * time.Second
)

// ErrKeyExhausted is returned when a session's send nonce hits RejectAfter.
var ErrKeyExhausted = errors.New("noise: key exhausted, rekey required")

// Session is the runtime transport state derived from a completed handshake —
// the equivalent of WireGuard's Keypair. It owns the pre-constructed AEAD
// ciphers, the monotonic send nonce, and the receive-side replay window.
//
// Unlike TransportKeys (the raw two keys the handshake yields), a Session is
// what the control and data planes actually use: SealNext stamps and bumps the
// nonce, OpenAt verifies the nonce against the replay window.
type Session struct {
	send    cipher.AEAD
	receive cipher.AEAD

	sendNonce atomic.Uint64
	replay    ReplayFilter // guarded by recvMu

	IsInitiator bool
	Created     time.Time
}

// NewSession promotes the handshake's TransportKeys into a live Session.
// isInitiator records which side we are (used by rekey timing).
func NewSession(keys TransportKeys, isInitiator bool) (*Session, error) {
	send, err := chacha20poly1305.New(keys.Send[:])
	if err != nil {
		return nil, err
	}
	recv, err := chacha20poly1305.New(keys.Recv[:])
	if err != nil {
		return nil, err
	}
	s := &Session{send: send, receive: recv, IsInitiator: isInitiator, Created: time.Now()}
	s.replay.Reset()
	return s, nil
}

// SessionFromKeys builds a Session directly from raw directional keys. Unlike
// NewSession (which consumes a handshake's TransportKeys on the machine that ran
// the handshake), this lets any PE reconstruct a data-plane session from the
// keys replicated in Raft (PRD §7.2) — the machine a client hopped to never ran
// the handshake yet must still decrypt its frames. send seals PE->client;
// recv opens client->PE. isInitiator is false (a PE is always the responder
// side of the original CE handshake) — it only affects rekey timing.
func SessionFromKeys(send, recv [32]byte) (*Session, error) {
	return NewSession(TransportKeys{Send: send, Recv: recv}, false)
}

// SealNext encrypts plaintext with the next send nonce and returns the counter
// used plus the ciphertext. The counter must travel on the wire so the peer
// can reconstruct the nonce for OpenAt.
func (s *Session) SealNext(plaintext, aad []byte) (counter uint64, ct []byte, err error) {
	counter = s.sendNonce.Add(1) - 1
	if counter >= RejectAfterMessages {
		s.sendNonce.Store(RejectAfterMessages)
		return 0, nil, ErrKeyExhausted
	}
	n := nonce(counter)
	return counter, s.send.Seal(nil, n[:], plaintext, aad), nil
}

// SealAt encrypts with an explicit counter — used for the fixed-counter
// control-plane frames (ClientAnswer / ServerAssign at counter 0) where a
// single message per direction makes a monotonic sequence unnecessary.
func (s *Session) SealAt(counter uint64, plaintext, aad []byte) ([]byte, error) {
	n := nonce(counter)
	return s.send.Seal(nil, n[:], plaintext, aad), nil
}

// OpenAt decrypts ciphertext received at counter, enforcing the replay window.
// checkReplay=false skips the window (used for the single control-plane frame
// where ordering is guaranteed by the request/response sequence).
func (s *Session) OpenAt(counter uint64, ct, aad []byte, checkReplay bool) ([]byte, error) {
	n := nonce(counter)
	pt, err := s.receive.Open(nil, n[:], ct, aad)
	if err != nil {
		return nil, err
	}
	if checkReplay && !s.replay.ValidateCounter(counter, RejectAfterMessages) {
		return nil, errors.New("noise: replayed or out-of-window counter")
	}
	return pt, nil
}
