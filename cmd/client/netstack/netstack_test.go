package netstack

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// ---- test fixtures ---------------------------------------------------------

// stubDialer captures every DialContext / ListenPacket call and signals a
// channel so tests can await the call instead of polling. Both dial paths
// return an error so the proxy path tears down immediately after capture.
type stubDialer struct {
	calls     atomic.Int32
	last      atomic.Pointer[string]
	dialCh    chan string // cap 16, non-blocking send; drains what tests care about
	listenCh  chan string
	listeners atomic.Int32
}

func newStubDialer() *stubDialer {
	// Generous buffers so concurrent-flow tests don't silently lose signals
	// when the test thread hasn't yet drained; calls counter is authoritative
	// but dialCh is what tests assert target strings against.
	return &stubDialer{
		dialCh:   make(chan string, 256),
		listenCh: make(chan string, 256),
	}
}

func (s *stubDialer) DialContext(_ context.Context, network, addr string) (net.Conn, error) {
	s.calls.Add(1)
	key := network + ":" + addr
	s.last.Store(&key)
	select {
	case s.dialCh <- key:
	default:
	}
	return nil, errors.New("stub: not dialing")
}

func (s *stubDialer) ListenPacket(_ context.Context, network, addr string) (net.PacketConn, error) {
	s.listeners.Add(1)
	key := network + ":" + addr
	select {
	case s.listenCh <- key:
	default:
	}
	return nil, errors.New("stub: not listening")
}

// stdCfg returns a Config populated with sensible defaults for the test
// matrix. `mode` selects the public-destination egress policy; Socks5Peer is
// always set so routing tables are identical across modes and only the
// post-stack decision changes.
func stdCfg(mode Mode, phys Dialer, hooks map[string]*atomic.Int32) Config {
	bump := func(name string) func([]byte) error {
		c := hooks[name]
		return func(_ []byte) error {
			if c != nil {
				c.Add(1)
			}
			return nil
		}
	}
	return Config{
		LocalIP: netip.MustParseAddr("10.0.0.5"),
		MTU:     1500,
		OverlayRanges: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/24"),
		},
		Mode:            mode,
		Socks5Peer:      netip.MustParseAddrPort("10.0.0.1:1080"),
		OnTunWrite:      bump("tun"),
		OnOverlayWrite:  bump("ovl"),
		OnOverlayBypass: bump("bypass"),
		PhysicalDialer:  phys,
	}
}

// ---- classifier: pre-stack (inbound route decision) ------------------------

// TestPreStackClassify covers the 4 destination categories × 2 SOCKS5 states
// axis of the HandleTunInbound decision. Rule-of-thumb: only the overlay
// category is affected at this layer; SOCKS5 availability does not move the
// pre-stack choice. But we still run the matrix to lock that in.
func TestPreStackClassify(t *testing.T) {
	type want int
	const (
		wantStack want = iota
		wantBypass
	)

	cases := []struct {
		name     string
		dst      netip.Addr
		expected want
	}{
		{"public", netip.MustParseAddr("8.8.8.8"), wantStack},
		{"private-nonoverlay", netip.MustParseAddr("192.168.1.1"), wantStack},
		{"overlay-peer", netip.MustParseAddr("10.0.0.7"), wantBypass},
		{"loopback", netip.MustParseAddr("127.0.0.1"), wantStack},
	}

	for _, mode := range []Mode{ModeSocks5, ModeDirect} {
		for _, tc := range cases {
			t.Run(scenarioName(mode, tc.name), func(t *testing.T) {
				phys := newStubDialer()
				hooks := map[string]*atomic.Int32{
					"tun": new(atomic.Int32), "ovl": new(atomic.Int32), "bypass": new(atomic.Int32),
				}
				s := newTestStack(t, stdCfg(mode, phys, hooks))
				defer s.Close()

				d, _ := s.classifyInbound(buildTCPSyn(netip.MustParseAddr("10.0.0.5"), tc.dst, 12345, 80))
				switch tc.expected {
				case wantStack:
					if d != decisionStack {
						t.Fatalf("expected decisionStack, got %v", d)
					}
				case wantBypass:
					if d != decisionOverlayBypass {
						t.Fatalf("expected decisionOverlayBypass, got %v", d)
					}
				}
			})
		}
	}
}

// TestPreStackBypassDispatch feeds a real IPv4 TCP SYN through HandleTunInbound
// for overlay-peer and public destinations, then checks that the overlay-peer
// packet flows exclusively through OnOverlayBypass (never touches gvisor) and
// that the public packet does NOT trigger OnOverlayBypass. The gvisor side
// effect (OnTunWrite for SYN-ACK) isn't asserted here because generating a
// valid-to-gvisor SYN across platforms is flakier than it's worth.
func TestPreStackBypassDispatch(t *testing.T) {
	phys := newStubDialer()
	hooks := map[string]*atomic.Int32{
		"tun": new(atomic.Int32), "ovl": new(atomic.Int32), "bypass": new(atomic.Int32),
	}
	s := newTestStack(t, stdCfg(ModeSocks5, phys, hooks))
	defer s.Close()

	s.HandleTunInbound(buildTCPSyn(netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("10.0.0.9"), 1, 80))
	if hooks["bypass"].Load() != 1 {
		t.Fatalf("overlay pkt did not hit OnOverlayBypass: %d", hooks["bypass"].Load())
	}
	if hooks["tun"].Load() != 0 {
		t.Fatalf("overlay pkt unexpectedly emitted on OnTunWrite")
	}

	before := hooks["bypass"].Load()
	s.HandleTunInbound(buildTCPSyn(netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("8.8.8.8"), 2, 443))
	if hooks["bypass"].Load() != before {
		t.Fatalf("public pkt incorrectly hit OnOverlayBypass")
	}
}

// ---- classifier: post-stack (dial decision) --------------------------------

// TestPostStackDial covers the same 4 categories × 2 SOCKS5 states matrix at
// the post-reassembly layer. This is the exact decision the TCP forwarder
// makes for each accepted flow. Overlay destinations don't appear here in
// practice (they're bypassed pre-stack) but we still exercise them to prove
// the classifier agrees even if something else injected one.
func TestPostStackDial(t *testing.T) {
	cases := []struct {
		name string
		dst  netip.Addr
	}{
		{"public", netip.MustParseAddr("8.8.8.8")},
		{"private-nonoverlay", netip.MustParseAddr("192.168.1.1")},
		{"overlay-peer", netip.MustParseAddr("10.0.0.9")},
		{"loopback", netip.MustParseAddr("127.0.0.1")},
	}

	for _, mode := range []Mode{ModeSocks5, ModeDirect} {
		for _, tc := range cases {
			t.Run(scenarioName(mode, tc.name), func(t *testing.T) {
				phys := newStubDialer()
				hooks := map[string]*atomic.Int32{
					"tun": new(atomic.Int32), "ovl": new(atomic.Int32), "bypass": new(atomic.Int32),
				}
				s := newTestStack(t, stdCfg(mode, phys, hooks))
				defer s.Close()

				got := s.classifyDial(tc.dst)
				expected := expectedDialDecision(mode, tc.dst)
				if got != expected {
					t.Fatalf("dst=%s mode=%s: expected %v, got %v", tc.dst, mode, expected, got)
				}
			})
		}
	}
}

// expectedDialDecision encodes the truth table for post-stack routing:
//   - Private dst (RFC1918/loopback/link-local/ULA) always ⇒ physical,
//     regardless of Mode. "Overlay peer" is RFC1918 too here, so it also
//     lands on physical if it somehow bypasses the pre-stack filter.
//   - Public dst ⇒ ModeSocks5 dials through SOCKS5, ModeDirect dials
//     through the physical NIC. There is no fallback between modes.
func expectedDialDecision(mode Mode, dst netip.Addr) dialDecision {
	if isPrivate(dst) {
		return dialPhysical
	}
	if mode == ModeSocks5 {
		return dialSocks5
	}
	return dialPhysical
}

// ---- helpers ---------------------------------------------------------------

func newTestStack(t *testing.T, cfg Config) *Stack {
	t.Helper()
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Drain goroutines get a short window to settle; the OnTunWrite hook
	// will only fire if gvisor actually emits a reply, which it won't for
	// the bypass path we primarily care about.
	time.Sleep(10 * time.Millisecond)
	return s
}

// buildTCPSyn crafts a minimal IPv4 TCP SYN packet with correct IP and TCP
// checksums so gvisor would accept it if injected. We don't rely on gvisor
// accepting it in most tests, but having it well-formed keeps future
// integration-level tests cheap.
func buildTCPSyn(src, dst netip.Addr, srcPort, dstPort uint16) []byte {
	const ipHdrLen = 20
	const tcpHdrLen = 20
	total := ipHdrLen + tcpHdrLen

	pkt := make([]byte, total)
	// IPv4 header.
	pkt[0] = 0x45                                     // version=4, IHL=5
	pkt[1] = 0                                        // DSCP/ECN
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	binary.BigEndian.PutUint16(pkt[4:6], 0)           // identification
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)      // flags=DF
	pkt[8] = 64                                       // TTL
	pkt[9] = 6                                        // protocol=TCP
	// checksum (pkt[10:12]) filled below
	copy(pkt[12:16], src.AsSlice())
	copy(pkt[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:ipHdrLen]))

	// TCP header.
	tcp := pkt[ipHdrLen:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], 0)   // seq
	binary.BigEndian.PutUint32(tcp[8:12], 0)  // ack
	tcp[12] = 5 << 4                          // data offset = 5 words
	tcp[13] = 0x02                            // flags = SYN
	binary.BigEndian.PutUint16(tcp[14:16], 65535) // window
	binary.BigEndian.PutUint16(tcp[18:20], 0)     // urgent
	// checksum (tcp[16:18]) filled below
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(src, dst, tcp))

	return pkt
}

func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpChecksum(src, dst netip.Addr, tcp []byte) uint16 {
	var sum uint32
	s := src.As4()
	d := dst.As4()
	sum += uint32(binary.BigEndian.Uint16(s[0:2]))
	sum += uint32(binary.BigEndian.Uint16(s[2:4]))
	sum += uint32(binary.BigEndian.Uint16(d[0:2]))
	sum += uint32(binary.BigEndian.Uint16(d[2:4]))
	sum += uint32(6)            // protocol
	sum += uint32(len(tcp))     // TCP length
	for i := 0; i+1 < len(tcp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcp[i:]))
	}
	if len(tcp)%2 == 1 {
		sum += uint32(tcp[len(tcp)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func scenarioName(mode Mode, dst string) string {
	return mode.String() + "/" + dst
}
