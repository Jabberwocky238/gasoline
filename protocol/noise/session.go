package noise

import (
	"crypto/cipher"
	"errors"
	"sync"
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

// Counter layout for the PE->client direction under multi-operator hopping
// (PRD §7.3). The 64-bit AEAD counter is partitioned:
//
//	[63:48]  operator tag (16 bits) — a stable small id per operator
//	[47:0]   per-operator monotonic sequence (48 bits)
//
// Two operators sharing one session's S2CKey therefore seal in DISJOINT counter
// sub-spaces, so the same (key, nonce) is never reused across operators — the
// AEAD-nonce-reuse hazard when a client hops. The client validates replay per
// operator tag (a window per sub-space), so frames from different operators
// don't shadow each other. The client->PE direction (one session, one operator
// at a time) leaves the tag zero.
const (
	counterSeqBits = 48
	counterSeqMask = (uint64(1) << counterSeqBits) - 1
)

// OperatorTagOf extracts the operator tag from a received counter.
func OperatorTagOf(counter uint64) uint16 { return uint16(counter >> counterSeqBits) }

// Session is the runtime transport state derived from a completed handshake —
// the equivalent of WireGuard's Keypair. It owns the pre-constructed AEAD
// ciphers, the monotonic send nonce, and the receive-side replay windows.
//
// Unlike TransportKeys (the raw two keys the handshake yields), a Session is
// what the control and data planes actually use: SealNext stamps and bumps the
// nonce, OpenAt verifies the nonce against the replay window.
type Session struct {
	send    cipher.AEAD
	receive cipher.AEAD

	// sendTag is OR'd into the high 16 bits of every send counter, partitioning
	// this operator's counter space from other operators sharing the key.
	sendTag   uint16
	sendNonce atomic.Uint64 // low 48 bits: the per-operator sequence

	// replays holds one anti-replay window per operator tag seen on the receive
	// side (client side, where frames arrive from multiple operators). Guarded
	// by recvMu. A single-operator peer only ever uses tag 0.
	recvMu  sync.Mutex
	replays map[uint16]*ReplayFilter

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
	s := &Session{
		send:        send,
		receive:     recv,
		replays:     make(map[uint16]*ReplayFilter),
		IsInitiator: isInitiator,
		Created:     time.Now(),
	}
	return s, nil
}

// SessionFromKeys builds a Session directly from raw directional keys, tagging
// its send counters with operatorTag (PRD §7.3). Unlike NewSession (which
// consumes a handshake's TransportKeys on the machine that ran the handshake),
// this lets any PE reconstruct a data-plane session from the keys replicated in
// Raft (PRD §7.2) — the machine a client hopped to never ran the handshake yet
// must still decrypt its frames. send seals PE->client; recv opens client->PE.
// isInitiator is false (a PE is always the responder side).
func SessionFromKeys(send, recv [32]byte, operatorTag uint16) (*Session, error) {
	s, err := NewSession(TransportKeys{Send: send, Recv: recv}, false)
	if err != nil {
		return nil, err
	}
	s.sendTag = operatorTag
	return s, nil
}

// SetOperatorTag sets the operator tag OR'd into this session's send counters.
// Used to stamp the home operator's live handshake session with its tag so its
// PE->client frames occupy a disjoint counter sub-space from hopped operators.
func (s *Session) SetOperatorTag(tag uint16) { s.sendTag = tag }

// SealNext encrypts plaintext with the next send nonce and returns the counter
// used plus the ciphertext. The counter is (sendTag << 48) | seq, so this
// operator's nonces never collide with another operator's under the same key.
// The counter travels on the wire so the peer reconstructs the nonce and reads
// back the operator tag for per-source replay validation.
func (s *Session) SealNext(plaintext, aad []byte) (counter uint64, ct []byte, err error) {
	seq := s.sendNonce.Add(1) - 1
	if seq >= counterSeqMask {
		s.sendNonce.Store(counterSeqMask)
		return 0, nil, ErrKeyExhausted
	}
	counter = (uint64(s.sendTag) << counterSeqBits) | seq
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

// OpenAt decrypts ciphertext received at counter, enforcing the replay window
// FOR THAT COUNTER'S OPERATOR TAG. Frames from different operators (distinct
// high 16 bits) are validated against separate windows, so a hop to another
// operator (whose sequence restarts) is not seen as a replay. checkReplay=false
// skips the window (the single control-plane frame, where ordering is
// guaranteed by the request/response sequence).
func (s *Session) OpenAt(counter uint64, ct, aad []byte, checkReplay bool) ([]byte, error) {
	n := nonce(counter)
	pt, err := s.receive.Open(nil, n[:], ct, aad)
	if err != nil {
		return nil, err
	}
	if checkReplay {
		tag := OperatorTagOf(counter)
		seq := counter & counterSeqMask
		s.recvMu.Lock()
		rf := s.replays[tag]
		if rf == nil {
			rf = &ReplayFilter{}
			rf.Reset()
			s.replays[tag] = rf
		}
		ok := rf.ValidateCounter(seq, counterSeqMask)
		s.recvMu.Unlock()
		if !ok {
			return nil, errors.New("noise: replayed or out-of-window counter")
		}
	}
	return pt, nil
}
