package tap

import (
	"net/netip"
	"sync"
)

// stagedQueueCap is the per-IP backlog limit. Once reached new packets
// for that destination are dropped until ARP resolves.
const stagedQueueCap = 4096

// stagedQueue is the per-destination-IP backlog of IP packets waiting on
// ARP resolution. Each entry is a freshly-allocated copy of the packet
// (the original buffer comes from the pool and is recycled immediately
// after staging — we cannot hold pool buffers across an unbounded delay).
type stagedQueue struct {
	frames [][]byte
}

// stagedIPPackets is the staging map keyed by destination IP.
type stagedIPPackets struct {
	mu sync.Mutex
	m  map[netip.Addr]*stagedQueue
}

func newStagedIPPackets() *stagedIPPackets {
	return &stagedIPPackets{m: make(map[netip.Addr]*stagedQueue)}
}

// enqueue adds a packet to the dst's backlog. Returns:
//
//	queued     : true if the packet entered the queue (false → dropped)
//	firstHit   : true if this enqueue created the queue (i.e. caller should
//	             emit the ARP request — we only ARP-request once per dst)
func (s *stagedIPPackets) enqueue(dst netip.Addr, ipPkt []byte) (queued, firstHit bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q, ok := s.m[dst]
	if !ok {
		q = &stagedQueue{frames: make([][]byte, 0, 16)}
		s.m[dst] = q
		firstHit = true
	}
	if len(q.frames) >= stagedQueueCap {
		return false, false
	}
	pkt := make([]byte, len(ipPkt))
	copy(pkt, ipPkt)
	q.frames = append(q.frames, pkt)
	return true, firstHit
}

// drain removes and returns all queued packets for dst.
// Caller takes ownership of the returned slices.
func (s *stagedIPPackets) drain(dst netip.Addr) [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	q, ok := s.m[dst]
	if !ok {
		return nil
	}
	delete(s.m, dst)
	return q.frames
}

// pendingCount returns the total number of staged packets across all queues.
func (s *stagedIPPackets) pendingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, q := range s.m {
		n += len(q.frames)
	}
	return n
}
