package fakeip

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// ---- Pool ------------------------------------------------------------------

func TestPoolStableMapping(t *testing.T) {
	p := mustPool(t, "198.18.0.0/24", 100)

	a := p.Lookup("example.com")
	b := p.Lookup("example.com")
	if a != b {
		t.Fatalf("same domain returned different IPs: %s vs %s", a, b)
	}
	dom, ok := p.Reverse(a)
	if !ok {
		t.Fatalf("reverse lookup failed for %s", a)
	}
	if dom != "example.com" {
		t.Fatalf("reverse: got %q, want example.com", dom)
	}
}

func TestPoolCanonicalization(t *testing.T) {
	p := mustPool(t, "198.18.0.0/24", 100)
	a := p.Lookup("Example.COM")
	b := p.Lookup("example.com.")
	c := p.Lookup("example.com")
	if a != b || b != c {
		t.Fatalf("non-canonical domains got distinct IPs: %s / %s / %s", a, b, c)
	}
	if p.Len() != 1 {
		t.Fatalf("expected 1 entry, got %d", p.Len())
	}
}

func TestPoolDistinctDomains(t *testing.T) {
	p := mustPool(t, "198.18.0.0/24", 100)
	a := p.Lookup("a.example")
	b := p.Lookup("b.example")
	if a == b {
		t.Fatalf("different domains mapped to same IP: %s", a)
	}
}

func TestPoolLRUEviction(t *testing.T) {
	// Tiny pool to force eviction.
	p := mustPool(t, "198.18.0.0/30", 2)

	ipA := p.Lookup("a.example")
	ipB := p.Lookup("b.example")

	// Inserting a third domain must evict the LRU entry. "a" is LRU.
	ipC := p.Lookup("c.example")

	if _, ok := p.Reverse(ipA); ok {
		t.Fatalf("expected a.example to be evicted; still reverse-resolves to %s", ipA)
	}
	if _, ok := p.Reverse(ipB); !ok {
		t.Fatalf("b.example should have survived; IP=%s", ipB)
	}
	if _, ok := p.Reverse(ipC); !ok {
		t.Fatalf("c.example should exist; IP=%s", ipC)
	}

	// Re-looking up "a" must produce a *new* binding (not the old IP).
	newA := p.Lookup("a.example")
	if newA == ipA {
		t.Fatalf("re-allocation after eviction reused old IP %s", ipA)
	}
}

func TestPoolAccessOrderTouchesLRU(t *testing.T) {
	p := mustPool(t, "198.18.0.0/30", 2)
	ipA := p.Lookup("a.example")
	_ = p.Lookup("b.example")
	// Touch A so B becomes LRU.
	if got := p.Lookup("a.example"); got != ipA {
		t.Fatalf("lookup returned different IP for a.example: %s vs %s", got, ipA)
	}
	// Inserting C evicts B (LRU), not A.
	_ = p.Lookup("c.example")
	if _, ok := p.Reverse(ipA); !ok {
		t.Fatalf("a.example (recently accessed) was wrongly evicted")
	}
}

func TestPoolContains(t *testing.T) {
	p := mustPool(t, "198.18.0.0/24", 10)
	if !p.Contains(netip.MustParseAddr("198.18.0.42")) {
		t.Fatal("Contains missed in-range address")
	}
	if p.Contains(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("Contains matched out-of-range address")
	}
}

func TestPoolRejectsInvalid(t *testing.T) {
	if _, err := New(PoolConfig{}); err == nil {
		t.Fatal("empty Range should fail")
	}
	if _, err := New(PoolConfig{Range: netip.MustParsePrefix("fc00::/8"), Size: 10}); err == nil {
		t.Fatal("IPv6 range should fail")
	}
	if _, err := New(PoolConfig{Range: netip.MustParsePrefix("198.18.0.0/24"), Size: 0}); err == nil {
		t.Fatal("zero Size should fail")
	}
	if _, err := New(PoolConfig{Range: netip.MustParsePrefix("198.18.0.0/24"), Size: 100000}); err == nil {
		t.Fatal("oversize Size should fail")
	}
}

// ---- Server: ShouldHijack policy ------------------------------------------

func TestShouldHijackMatrix(t *testing.T) {
	p := mustPool(t, "198.18.0.0/15", 4096)
	s, err := NewServer(Config{
		Pool: p,
		OverlayRanges: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/24"),
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	cases := []struct {
		name string
		dst  string
		want bool
	}{
		{"overlay-peer", "10.0.0.1", false},            // pass through
		{"overlay-self", "10.0.0.5", false},            // pass through
		{"public-8.8.8.8", "8.8.8.8", true},            // hijack
		{"lan-192.168.1.1", "192.168.1.1", true},       // hijack (key case)
		{"lan-172.16.0.1", "172.16.0.1", true},         // hijack
		{"lan-10.1.1.1 (outside overlay)", "10.1.1.1", true}, // hijack
		{"loopback", "127.0.0.1", true},                // hijack
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.ShouldHijack(netip.MustParseAddr(tc.dst)); got != tc.want {
				t.Fatalf("dst=%s: got %v, want %v", tc.dst, got, tc.want)
			}
		})
	}
}

// ---- Server: UDP query/response round-trip --------------------------------

func TestServeUDPARecord(t *testing.T) {
	p := mustPool(t, "198.18.0.0/24", 100)
	s, err := NewServer(Config{Pool: p, DNSTTL: 300})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	query := mustQuery(t, 0x1234, "example.com.", dnsmessage.TypeA)
	resp := s.ServeUDP(query)
	if resp == nil {
		t.Fatal("ServeUDP returned nil for a valid A query")
	}

	var msg dnsmessage.Message
	if err := msg.Unpack(resp); err != nil {
		t.Fatalf("Unpack resp: %v", err)
	}
	if msg.Header.ID != 0x1234 {
		t.Fatalf("ID mismatch: got %#x want 0x1234", msg.Header.ID)
	}
	if !msg.Header.Response {
		t.Fatal("QR bit not set")
	}
	if msg.Header.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("RCode: got %v want Success", msg.Header.RCode)
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answers))
	}
	ar, ok := msg.Answers[0].Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("answer not AResource: %T", msg.Answers[0].Body)
	}
	ip := netip.AddrFrom4(ar.A)
	if !p.Contains(ip) {
		t.Fatalf("returned IP %s outside pool range", ip)
	}
	if msg.Answers[0].Header.TTL != 300 {
		t.Fatalf("TTL: got %d want 300", msg.Answers[0].Header.TTL)
	}

	// Reverse must agree.
	dom, ok := p.Reverse(ip)
	if !ok || dom != "example.com" {
		t.Fatalf("reverse: ok=%v dom=%q", ok, dom)
	}
}

func TestServeUDPAAAAEmptyAnswer(t *testing.T) {
	p := mustPool(t, "198.18.0.0/24", 100)
	s, _ := NewServer(Config{Pool: p})

	query := mustQuery(t, 0x2222, "example.com.", dnsmessage.TypeAAAA)
	resp := s.ServeUDP(query)
	if resp == nil {
		t.Fatal("ServeUDP returned nil for a valid AAAA query")
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(resp); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if msg.Header.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("RCode: got %v want Success", msg.Header.RCode)
	}
	if len(msg.Answers) != 0 {
		t.Fatalf("expected 0 answers for AAAA, got %d", len(msg.Answers))
	}
}

func TestServeUDPMalformedDrops(t *testing.T) {
	p := mustPool(t, "198.18.0.0/24", 100)
	s, _ := NewServer(Config{Pool: p})
	if got := s.ServeUDP([]byte{0x00, 0x00}); got != nil {
		t.Fatalf("expected nil for truncated query, got %d bytes", len(got))
	}
	if got := s.ServeUDP(nil); got != nil {
		t.Fatalf("expected nil for nil query, got %d bytes", len(got))
	}
}

// ---- Server: TCP length-prefixed round-trip -------------------------------

func TestServeTCPLengthPrefixed(t *testing.T) {
	p := mustPool(t, "198.18.0.0/24", 100)
	s, _ := NewServer(Config{Pool: p, DNSTTL: 120})

	// Build two concatenated queries so we exercise the loop.
	q1 := mustQuery(t, 0x0001, "one.example.", dnsmessage.TypeA)
	q2 := mustQuery(t, 0x0002, "two.example.", dnsmessage.TypeA)

	var in bytes.Buffer
	writeFramed(&in, q1)
	writeFramed(&in, q2)

	var out bytes.Buffer
	conn := &rwPair{r: &in, w: &out}
	if err := s.ServeTCP(conn); err != nil {
		t.Fatalf("ServeTCP: %v", err)
	}

	// Two framed responses in order.
	resp1 := readFramed(t, &out)
	resp2 := readFramed(t, &out)

	var m1, m2 dnsmessage.Message
	if err := m1.Unpack(resp1); err != nil {
		t.Fatalf("unpack resp1: %v", err)
	}
	if err := m2.Unpack(resp2); err != nil {
		t.Fatalf("unpack resp2: %v", err)
	}
	if m1.Header.ID != 0x0001 || m2.Header.ID != 0x0002 {
		t.Fatalf("IDs: %#x %#x", m1.Header.ID, m2.Header.ID)
	}
	if len(m1.Answers) != 1 || len(m2.Answers) != 1 {
		t.Fatalf("answer counts: %d %d", len(m1.Answers), len(m2.Answers))
	}
}

// ---- helpers --------------------------------------------------------------

func mustPool(t *testing.T, prefix string, size int) *Pool {
	t.Helper()
	p, err := New(PoolConfig{
		Range: netip.MustParsePrefix(prefix),
		Size:  size,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func mustQuery(t *testing.T, id uint16, name string, qtype dnsmessage.Type) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatalf("NewName(%s): %v", name, err)
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{
			{Name: n, Type: qtype, Class: dnsmessage.ClassINET},
		},
	}
	out, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack query: %v", err)
	}
	return out
}

func writeFramed(w io.Writer, msg []byte) {
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(msg)))
	_, _ = w.Write(hdr[:])
	_, _ = w.Write(msg)
}

func readFramed(t *testing.T, r io.Reader) []byte {
	t.Helper()
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		t.Fatalf("read frame len: %v", err)
	}
	n := binary.BigEndian.Uint16(hdr[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("read frame body: %v", err)
	}
	return buf
}

// rwPair stitches a reader and writer into a single io.ReadWriter so we
// don't have to spin up a net.Pipe to test ServeTCP.
type rwPair struct {
	r io.Reader
	w io.Writer
}

func (p *rwPair) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *rwPair) Write(b []byte) (int, error) { return p.w.Write(b) }
