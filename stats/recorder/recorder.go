package recorder

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"
)

const (
	windowSize = 60 // 60 slots, each 1 second → 60s sliding window
)

// slot holds the byte count for a 1-second interval.
type slot struct {
	bytes uint64
	ts    int64 // unix second this slot belongs to
}

// slidingWindow tracks bytes over a fixed-size ring buffer of 1-second slots.
type slidingWindow struct {
	mu    sync.Mutex
	slots [windowSize]slot
	head  int // next slot to write
}

// add records n bytes at the current time.
func (w *slidingWindow) add(n uint64) {
	now := time.Now().Unix()
	w.mu.Lock()
	defer w.mu.Unlock()

	cur := &w.slots[w.head]
	if cur.ts == now {
		cur.bytes += n
		return
	}
	// Advance head
	w.head = (w.head + 1) % windowSize
	w.slots[w.head] = slot{bytes: n, ts: now}
}

// rate returns the average bytes/sec over the last `seconds` seconds (max windowSize).
func (w *slidingWindow) rate(seconds int) float64 {
	if seconds <= 0 || seconds > windowSize {
		seconds = windowSize
	}
	now := time.Now().Unix()
	cutoff := now - int64(seconds)

	w.mu.Lock()
	defer w.mu.Unlock()

	var total uint64
	for i := 0; i < windowSize; i++ {
		s := &w.slots[i]
		if s.ts > cutoff && s.ts <= now {
			total += s.bytes
		}
	}
	return float64(total) / float64(seconds)
}

// SessionStats holds traffic counters and live rate for a single client session.
type SessionStats struct {
	SessionID   [16]byte  `json:"-"`
	VNetID      [16]byte  `json:"-"`
	AuthID      string    `json:"auth_id"`
	RemoteAddr  string    `json:"remote_addr"`
	ConnectedAt time.Time `json:"connected_at"`

	TxBytes   atomic.Uint64 `json:"-"`
	RxBytes   atomic.Uint64 `json:"-"`
	TxPackets atomic.Uint64 `json:"-"`
	RxPackets atomic.Uint64 `json:"-"`

	txWindow slidingWindow
	rxWindow slidingWindow
}

// TxRate returns the average tx bytes/sec over the last n seconds.
func (s *SessionStats) TxRate(seconds int) float64 { return s.txWindow.rate(seconds) }

// RxRate returns the average rx bytes/sec over the last n seconds.
func (s *SessionStats) RxRate(seconds int) float64 { return s.rxWindow.rate(seconds) }

// Snapshot returns a JSON-friendly snapshot of this session's stats.
type Snapshot struct {
	SessionID   string    `json:"session_id"`
	VNetID      string    `json:"vnet_id"`
	AuthID      string    `json:"auth_id"`
	RemoteAddr  string    `json:"remote_addr"`
	ConnectedAt time.Time `json:"connected_at"`
	TxBytes     uint64    `json:"tx_bytes"`
	RxBytes     uint64    `json:"rx_bytes"`
	TxPackets   uint64    `json:"tx_packets"`
	RxPackets   uint64    `json:"rx_packets"`
	TxBytesPerSec float64 `json:"tx_bytes_per_sec"` // 5s average
	RxBytesPerSec float64 `json:"rx_bytes_per_sec"` // 5s average
}

func (s *SessionStats) snapshot() *Snapshot {
	return &Snapshot{
		SessionID:     hexEncode(s.SessionID[:]),
		VNetID:        hexEncode(s.VNetID[:]),
		AuthID:        s.AuthID,
		RemoteAddr:    s.RemoteAddr,
		ConnectedAt:   s.ConnectedAt,
		TxBytes:       s.TxBytes.Load(),
		RxBytes:       s.RxBytes.Load(),
		TxPackets:     s.TxPackets.Load(),
		RxPackets:     s.RxPackets.Load(),
		TxBytesPerSec: s.TxRate(5),
		RxBytesPerSec: s.RxRate(5),
	}
}

func (s *SessionStats) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.snapshot())
}

func hexEncode(b []byte) string {
	const hextable = "0123456789abcdef"
	dst := make([]byte, len(b)*2)
	for i, v := range b {
		dst[i*2] = hextable[v>>4]
		dst[i*2+1] = hextable[v&0x0f]
	}
	return string(dst)
}

// Recorder tracks per-session traffic statistics with sliding-window rates.
type Recorder struct {
	mu       sync.RWMutex
	sessions map[[16]byte]*SessionStats
}

func New() *Recorder {
	return &Recorder{
		sessions: make(map[[16]byte]*SessionStats),
	}
}

func (r *Recorder) Register(sessionID, vnetID [16]byte, authID, remoteAddr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[sessionID] = &SessionStats{
		SessionID:   sessionID,
		VNetID:      vnetID,
		AuthID:      authID,
		RemoteAddr:  remoteAddr,
		ConnectedAt: time.Now(),
	}
}

func (r *Recorder) Unregister(sessionID [16]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, sessionID)
}

func (r *Recorder) RecordTx(sessionID [16]byte, bytes uint64) {
	r.mu.RLock()
	s, ok := r.sessions[sessionID]
	r.mu.RUnlock()
	if !ok {
		return
	}
	s.TxBytes.Add(bytes)
	s.TxPackets.Add(1)
	s.txWindow.add(bytes)
}

func (r *Recorder) RecordRx(sessionID [16]byte, bytes uint64) {
	r.mu.RLock()
	s, ok := r.sessions[sessionID]
	r.mu.RUnlock()
	if !ok {
		return
	}
	s.RxBytes.Add(bytes)
	s.RxPackets.Add(1)
	s.rxWindow.add(bytes)
}

func (r *Recorder) Get(sessionID [16]byte) *SessionStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sessions[sessionID]
}

func (r *Recorder) All() []*Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*Snapshot, 0, len(r.sessions))
	for _, s := range r.sessions {
		result = append(result, s.snapshot())
	}
	return result
}

func (r *Recorder) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

func (r *Recorder) TotalBytes() (tx, rx uint64) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.sessions {
		tx += s.TxBytes.Load()
		rx += s.RxBytes.Load()
	}
	return
}
