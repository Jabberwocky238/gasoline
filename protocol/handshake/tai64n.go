package handshake

import (
	"encoding/binary"
	"time"
)

// tai64nEpoch offsets Unix time onto the TAI64 label space (WireGuard uses the
// same constant). We do not track leap seconds — monotonicity is all the
// replay check needs.
const tai64nEpoch = 0x400000000000000a

// tai64n returns the current time as a 12-byte TAI64N label:
// 8 bytes of seconds (big-endian, TAI-offset) + 4 bytes of nanoseconds.
// The server records the greatest label seen per static key and rejects any
// msg1 carrying an older one (PRD §3.2 replay protection).
func tai64n() []byte {
	now := time.Now()
	out := make([]byte, 12)
	binary.BigEndian.PutUint64(out[0:8], tai64nEpoch+uint64(now.Unix()))
	binary.BigEndian.PutUint32(out[8:12], uint32(now.Nanosecond()))
	return out
}
