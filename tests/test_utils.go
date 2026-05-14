package tests

import (
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/transport"
	singTun "github.com/sagernet/sing-tun"
)

// Compile-time check: MockTun satisfies singTun.Tun, so it can be
// wrapped via tun.NewFromSingTun(mt) and handed to Client.SetTun.
var _ singTun.Tun = (*MockTun)(nil)

// MockTun is an in-memory stand-in for device/tun.Tun used by routing
// and config-propagation tests. It has no kernel surface — every byte
// stays in process memory — so tests can drive both sides of a TUN
// without root, without OS routes, and without flakiness from real
// network state.
//
// Three things make it useful as a test fixture:
//
//  1. Read / Write match the *tun.Tun shape, so a future client-side
//     refactor that swaps the concrete TUN for an interface plugs this
//     in directly.
//  2. The most recent MockTunOptions handed to Configure (or to the
//     constructor) is held as the authoritative config. Tests assert
//     against Options() to verify operator-pushed configuration
//     (assigned IP, MTU, pushed routes, …) actually lands.
//  3. Every packet Write()n into the mock is captured in a fixed-size
//     ring buffer (oldest dropped on overflow), letting tests inspect
//     what the operator would have delivered to the host stack without
//     racing on a channel.
//
// Direction convention matches device/tun.Tun:
//
//	Write(pkt)  — caller delivers a packet "down" to the TUN (operator
//	              -> kernel stack on a real TUN). Captured in the ring.
//	Read(buf)   — caller pulls the next packet "up" from the TUN
//	              (kernel stack -> operator on a real TUN). Tests queue
//	              packets via Inject before Read returns them.
type MockTun struct {
	mu      sync.Mutex
	options MockTunOptions
	closed  bool

	ring *packetRing

	// outbox carries packets the test injected for Read() to deliver.
	// Buffered so Inject() never blocks for the common test cadence;
	// once full, Inject returns ErrOutboxFull.
	outbox chan []byte

	// done is closed on Close(); Read drains then returns io.EOF.
	done chan struct{}
}

// MockTunOptions captures the configuration a real TUN would have been
// programmed with. Fields are the subset that operator-pushed config
// realistically touches; expand as new control-plane ops grow.
type MockTunOptions struct {
	Name    string
	Address netip.Prefix   // assigned host address (e.g. 10.0.0.5/24)
	MTU     int            // 0 means "unset"
	Routes  []netip.Prefix // additional reachable prefixes
}

// MockTunDefaultRingCap is the default capture-ring depth. Override per
// test with NewMockTunSized when a particular run needs more history.
const MockTunDefaultRingCap = 256

// MockTunDefaultOutboxCap is the default Inject buffer depth.
const MockTunDefaultOutboxCap = 64

// ErrTunClosed is returned by Read / Write after Close.
var ErrTunClosed = fmt.Errorf("mocktun: closed")

// ErrOutboxFull is returned by Inject when the outbox is saturated.
var ErrOutboxFull = fmt.Errorf("mocktun: outbox full")

// NewMockTun builds a MockTun with default ring + outbox capacities.
func NewMockTun(opts MockTunOptions) *MockTun {
	return NewMockTunSized(opts, MockTunDefaultRingCap, MockTunDefaultOutboxCap)
}

// NewMockTunSized lets a test pick the ring and outbox capacities.
// Both must be > 0.
func NewMockTunSized(opts MockTunOptions, ringCap, outboxCap int) *MockTun {
	if ringCap <= 0 {
		ringCap = MockTunDefaultRingCap
	}
	if outboxCap <= 0 {
		outboxCap = MockTunDefaultOutboxCap
	}
	return &MockTun{
		options: opts.clone(),
		ring:    newPacketRing(ringCap),
		outbox:  make(chan []byte, outboxCap),
		done:    make(chan struct{}),
	}
}

// Name satisfies singTun.Tun. Returns the name captured in the
// MockTunOptions snapshot (default "" if never configured).
func (m *MockTun) Name() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.options.Name, nil
}

// Start is a no-op on the mock; included so callers that treat *tun.Tun
// and *MockTun interchangeably don't need a special case.
func (m *MockTun) Start() error { return nil }

// UpdateRouteOptions satisfies singTun.Tun. It folds the relevant
// fields of a sing-tun Options struct into the MockTun's captured
// MockTunOptions so tests can assert that operator-pushed route /
// address updates flowed all the way through tun.UpdateRouteOptions.
//
// Only the fields tests realistically care about are translated —
// Name, primary v4/v6 address, MTU, and the route-prefix list.
func (m *MockTun) UpdateRouteOptions(opts singTun.Options) error {
	if m.IsClosed() {
		return ErrTunClosed
	}
	merged := MockTunOptions{
		Name:    opts.Name,
		MTU:     int(opts.MTU),
		Address: firstPrefix(opts.Inet4Address, opts.Inet6Address),
		Routes:  append([]netip.Prefix(nil), routeList(opts)...),
	}
	m.mu.Lock()
	m.options = merged
	m.mu.Unlock()
	return nil
}

// firstPrefix returns the first prefix from any of the supplied lists,
// preferring IPv4 over IPv6.
func firstPrefix(lists ...[]netip.Prefix) netip.Prefix {
	for _, lst := range lists {
		if len(lst) > 0 {
			return lst[0]
		}
	}
	return netip.Prefix{}
}

// routeList collects the per-family route prefixes from a sing-tun
// Options struct into a single slice.
func routeList(opts singTun.Options) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(opts.Inet4RouteAddress)+len(opts.Inet6RouteAddress))
	out = append(out, opts.Inet4RouteAddress...)
	out = append(out, opts.Inet6RouteAddress...)
	return out
}

// Close releases internal channels and unblocks any pending Read.
// Safe to call more than once.
func (m *MockTun) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	close(m.done)
	return nil
}

// IsClosed reports whether Close has been called.
func (m *MockTun) IsClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

// Write captures one packet as if delivered down to the kernel stack
// and stores a copy in the ring buffer. Always returns len(p), nil
// unless the tun is closed.
func (m *MockTun) Write(p []byte) (int, error) {
	if m.IsClosed() {
		return 0, ErrTunClosed
	}
	m.ring.push(p)
	return len(p), nil
}

// Read blocks until the test queues a packet via Inject, or the mock
// is closed. On close, returns 0, io.EOF (after draining any pending
// outbox entries) — matching the convention real os.File-backed TUNs
// give to callers when the descriptor closes.
func (m *MockTun) Read(p []byte) (int, error) {
	select {
	case pkt, ok := <-m.outbox:
		if !ok {
			return 0, io.EOF
		}
		n := copy(p, pkt)
		return n, nil
	case <-m.done:
		// Drain anything still queued so tests don't lose injected
		// packets that raced with Close.
		select {
		case pkt := <-m.outbox:
			n := copy(p, pkt)
			return n, nil
		default:
			return 0, io.EOF
		}
	}
}

// ReadWithTimeout is a non-blocking variant for tests that want a
// hard deadline. Returns (0, nil) on timeout (no error).
func (m *MockTun) ReadWithTimeout(p []byte, d time.Duration) (int, error) {
	select {
	case pkt, ok := <-m.outbox:
		if !ok {
			return 0, io.EOF
		}
		return copy(p, pkt), nil
	case <-time.After(d):
		return 0, nil
	case <-m.done:
		return 0, io.EOF
	}
}

// Inject queues a packet for the next Read to return. Returns
// ErrOutboxFull if the buffer is saturated and ErrTunClosed after
// Close. The packet is copied so the caller can reuse its slice.
func (m *MockTun) Inject(p []byte) error {
	if m.IsClosed() {
		return ErrTunClosed
	}
	cp := append([]byte(nil), p...)
	select {
	case m.outbox <- cp:
		return nil
	default:
		return ErrOutboxFull
	}
}

// Configure replaces the captured options snapshot. This is the hook
// callers use to record an operator-pushed config update — e.g. a new
// assigned IP from a PrefixChanged op, or a fresh route batch from a
// RoutePush op. The struct is deep-copied so post-call mutations on
// opts don't bleed through.
func (m *MockTun) Configure(opts MockTunOptions) {
	m.mu.Lock()
	m.options = opts.clone()
	m.mu.Unlock()
}

// Options returns a deep copy of the current configuration snapshot.
// Tests assert against this to verify operator-pushed config landed.
func (m *MockTun) Options() MockTunOptions {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.options.clone()
}

// Received returns a copy of every packet currently held in the ring
// buffer, oldest first. Once the ring wraps, only the most recent
// ring-cap packets are visible — older entries have been overwritten.
func (m *MockTun) Received() [][]byte {
	return m.ring.snapshot()
}

// ReceivedCount returns the number of packets currently held in the
// ring (saturates at the ring capacity once it has wrapped).
func (m *MockTun) ReceivedCount() int {
	return m.ring.len()
}

// ResetReceived clears the capture ring (does not affect Options or
// the outbox). Useful between sub-tests that want a clean slate.
func (m *MockTun) ResetReceived() {
	m.ring.reset()
}

// clone returns a deep copy of MockTunOptions — Routes is a fresh slice.
func (o MockTunOptions) clone() MockTunOptions {
	cp := o
	if len(o.Routes) > 0 {
		cp.Routes = append([]netip.Prefix(nil), o.Routes...)
	}
	return cp
}

// --------------- ring buffer ---------------

// packetRing is a fixed-capacity circular buffer of packet payloads.
// Once full, the next push overwrites the oldest entry. Each slot
// owns its own copy of the bytes — the caller can reuse its source
// buffer immediately after push.
type packetRing struct {
	mu   sync.Mutex
	data [][]byte
	head int  // next write index
	full bool // true once head has wrapped
	cap  int
}

func newPacketRing(capacity int) *packetRing {
	return &packetRing{data: make([][]byte, capacity), cap: capacity}
}

func (r *packetRing) push(p []byte) {
	cp := append([]byte(nil), p...)
	r.mu.Lock()
	r.data[r.head] = cp
	r.head = (r.head + 1) % r.cap
	if r.head == 0 {
		r.full = true
	}
	r.mu.Unlock()
}

func (r *packetRing) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.full {
		return r.cap
	}
	return r.head
}

// snapshot returns every live entry, oldest first.
func (r *packetRing) snapshot() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.full {
		out := make([][]byte, r.head)
		for i := 0; i < r.head; i++ {
			out[i] = append([]byte(nil), r.data[i]...)
		}
		return out
	}
	out := make([][]byte, 0, r.cap)
	for i := r.head; i < r.cap; i++ {
		out = append(out, append([]byte(nil), r.data[i]...))
	}
	for i := 0; i < r.head; i++ {
		out = append(out, append([]byte(nil), r.data[i]...))
	}
	return out
}

// --------------- pump helpers ---------------
//
// These wire a MockTun to a transport.Conn in both directions, so a
// test sees the same data path a real client would: app -> tun ->
// conn (outbound) and conn -> tun -> app (inbound).
//
// Each helper returns immediately and runs to completion when either
// the conn or the tun closes — neither logs nor calls t.Fatal, so
// they're safe to spawn from any goroutine.

// PumpTunToConn forwards packets the test Inject()s into tun onward to
// conn.WritePacket. This is the "app -> kernel TUN -> wire" direction.
func PumpTunToConn(tun *MockTun, conn transport.Conn) {
	buf := make([]byte, common.MaxPacketSize)
	for {
		n, err := tun.Read(buf)
		if err != nil || n == 0 {
			return
		}
		if err := conn.WritePacket(buf[:n]); err != nil {
			return
		}
	}
}

// PumpConnToTun forwards packets read off conn into tun.Write, so they
// land in the ring buffer. This is the "wire -> kernel TUN -> app"
// direction. v3 (datactrl) frames are dropped — they would be handled
// in the client; the host-stack-shaped TUN never sees them.
func PumpConnToTun(conn transport.Conn, tun *MockTun) {
	buf := make([]byte, common.MaxPacketSize)
	for {
		n, err := conn.ReadPacket(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		if buf[0]>>4 == 3 {
			continue // datactrl: not an IP packet, never delivered upstairs
		}
		if _, err := tun.Write(buf[:n]); err != nil {
			return
		}
	}
}

func (r *packetRing) reset() {
	r.mu.Lock()
	r.head = 0
	r.full = false
	for i := range r.data {
		r.data[i] = nil
	}
	r.mu.Unlock()
}
