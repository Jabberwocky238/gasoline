package noise

// ReplayFilter rejects replayed frames by tracking a sliding window of
// received counters, per RFC 6479. Adapted from WireGuard's replay.Filter
// (MIT). Not safe for concurrent use — hold the receiver's lock.
//
// The zero value is an empty filter ready to use.

type block = uint64

const (
	blockBitLog = 6                // 1<<6 == 64 bits per block
	blockBits   = 1 << blockBitLog // 64
	ringBlocks  = 1 << 7           // 128 blocks
	windowSize  = (ringBlocks - 1) * blockBits
	blockMask   = ringBlocks - 1
	bitMask     = blockBits - 1
)

// ReplayFilter is the RFC 6479 sliding-window anti-replay state.
type ReplayFilter struct {
	last uint64
	ring [ringBlocks]block
}

// Reset clears the filter to empty.
func (f *ReplayFilter) Reset() {
	f.last = 0
	f.ring[0] = 0
}

// ValidateCounter returns true iff counter is fresh (never seen and within the
// window) for the given limit (the nonce space; counters >= limit are always
// rejected). A true return marks the counter consumed.
func (f *ReplayFilter) ValidateCounter(counter, limit uint64) bool {
	if counter >= limit {
		return false
	}
	indexBlock := counter >> blockBitLog
	if counter > f.last { // move window forward
		current := f.last >> blockBitLog
		diff := indexBlock - current
		if diff > ringBlocks {
			diff = ringBlocks // cap: clear the whole ring
		}
		for i := current + 1; i <= current+diff; i++ {
			f.ring[i&blockMask] = 0
		}
		f.last = counter
	} else if f.last-counter > windowSize { // behind the window
		return false
	}
	indexBlock &= blockMask
	indexBit := counter & bitMask
	old := f.ring[indexBlock]
	newv := old | 1<<indexBit
	f.ring[indexBlock] = newv
	return old != newv
}
