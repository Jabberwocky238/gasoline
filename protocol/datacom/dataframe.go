// dataframe.go — the gasoline DATA-PLANE frame: the encrypted envelope every
// IP packet travels in between a client (CE) and an operator (PE). The wire
// layout is fixed (PRD §7.3):
//
//	offset  size  field
//	0       6     SessionTag  (first 6 bytes of the SessionID; PE uses it to
//	                           locate the session's transport keys — it is a
//	                           decryption-key index, NOT a routing key)
//	6       8     Counter     (big-endian AEAD nonce, monotonic per key)
//	14      n     Ciphertext  (ChaCha20-Poly1305(key, Counter, ip_pkt);
//	                           n = plaintext_len + 16-byte Poly1305 tag)
//
// There is no DstTag: the PE decrypts, then routes on the plaintext dst IP
// (PRD §5.4.1). SessionTag and Counter travel in the clear (a nonce needn't be
// secret; the tag is just an index). Integrity of the whole payload rests on
// the Poly1305 tag — a forged frame fails AEAD open and is dropped.
package datacom

import (
	"encoding/binary"
	"fmt"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/noise"
)

const (
	TagSize     = 6
	CounterSize = 8
	// HeaderSize is the clear-text prefix before the ciphertext.
	HeaderSize = TagSize + CounterSize // 14

	tagOffset     = 0
	counterOffset = 6
	ctOffset      = 14
)

// aadData domain-separates data-plane frames from the auth and assign control
// planes, which seal under the same session keys with their own AADs.
var aadData = []byte("gasoline-data-v1")

// SessionTag is the 6-byte lookup key derived from a SessionID.
type SessionTag [TagSize]byte

// TagOf returns the SessionTag for a SessionID (its first 6 bytes).
func TagOf(sid protocol.SessionID_Ty) SessionTag {
	return SessionTag(sid[:TagSize])
}

// Seal encrypts one IP packet into a data frame under sess, stamping tag and
// the session's next send counter. The returned slice is a fresh allocation
// owning tag||counter||ciphertext.
func Seal(sess *noise.Session, tag SessionTag, ipPkt []byte) ([]byte, error) {
	counter, ct, err := sess.SealNext(ipPkt, aadData)
	if err != nil {
		return nil, err
	}
	frame := make([]byte, HeaderSize+len(ct))
	copy(frame[tagOffset:], tag[:])
	binary.BigEndian.PutUint64(frame[counterOffset:ctOffset], counter)
	copy(frame[ctOffset:], ct)
	return frame, nil
}

// ParseHeader splits a received frame into its tag, counter and ciphertext
// without decrypting. The PE uses the tag to find the session's keys before it
// can open the ciphertext.
func ParseHeader(frame []byte) (tag SessionTag, counter uint64, ct []byte, err error) {
	if len(frame) < HeaderSize {
		return SessionTag{}, 0, nil, fmt.Errorf("dataframe: short frame %d < %d", len(frame), HeaderSize)
	}
	copy(tag[:], frame[tagOffset:counterOffset])
	counter = binary.BigEndian.Uint64(frame[counterOffset:ctOffset])
	return tag, counter, frame[ctOffset:], nil
}

// Open decrypts a data frame's ciphertext under sess at counter. checkReplay
// enables the sliding replay window (UDP path); QUIC callers pass false since
// the transport already guarantees ordering and dedup (PRD §7.5).
func Open(sess *noise.Session, counter uint64, ct []byte, checkReplay bool) ([]byte, error) {
	return sess.OpenAt(counter, ct, aadData, checkReplay)
}
