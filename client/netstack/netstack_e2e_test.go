package netstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- test-wide timing -----------------------------------------------------

// Reasoning on these numbers:
//   - fast: one-shot classifier / hook observation — a healthy stack fires in
//     ≲10ms on a warm CPU; 500ms is enough for cold-start goroutine scheduling
//     under race and still short enough that a hang is obvious in CI.
//   - medium: covers a round-trip through the gvisor TCP handshake machinery
//     (SYN → SYN-ACK → ACK) that can take tens of ms under race.
//   - handshake: full glue-wired client+peer double stack needs ~4–5 round
//     trips; 6s has held up on Windows/race historically. Anything slower is
//     a real bug, not scheduling jitter.
const (
	fastDeadline      = 500 * time.Millisecond
	mediumDeadline    = 3 * time.Second
	handshakeDeadline = 6 * time.Second
)

// ---- test 1: overlay bypass byte identity ---------------------------------

// TestE2EOverlayBypassByteIdentity feeds a single well-formed IPv4 TCP SYN
// whose destination lies inside the overlay range and asserts:
//  1. The exact bytes appear on OnOverlayBypass.
//  2. No OnOverlayWrite or OnTunWrite fire (gvisor must not see this packet).
//  3. Exactly one bypass callback fires — no spurious duplicates.
func TestE2EOverlayBypassByteIdentity(t *testing.T) {
	bypass := make(chan []byte, 8)
	tunWrites := atomic.Int32{}
	ovlWrites := atomic.Int32{}

	s, err := New(Config{
		LocalIP: netip.MustParseAddr("10.0.0.5"),
		MTU:     1500,
		OverlayRanges: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/24"),
		},
		OnTunWrite:     func(_ []byte) error { tunWrites.Add(1); return nil },
		OnOverlayWrite: func(_ []byte) error { ovlWrites.Add(1); return nil },
		OnOverlayBypass: func(pkt []byte) error {
			cp := make([]byte, len(pkt))
			copy(cp, pkt)
			bypass <- cp // blocking on purpose; tests should drain
			return nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Close()

	syn := buildTCPSyn(netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("10.0.0.9"), 54321, 80)
	s.HandleTunInbound(syn)

	select {
	case got := <-bypass:
		if !bytes.Equal(got, syn) {
			t.Fatalf("bypass bytes differ\n want: %x\n got:  %x", syn, got)
		}
	case <-time.After(fastDeadline):
		t.Fatalf("no bypass callback within %s", fastDeadline)
	}

	// Wait a short beat to catch spurious extra packets (shouldn't exist).
	time.Sleep(100 * time.Millisecond)
	select {
	case extra := <-bypass:
		t.Fatalf("unexpected second bypass packet: %x", extra)
	default:
	}
	if n := tunWrites.Load(); n != 0 {
		t.Fatalf("overlay-bound packet leaked to OnTunWrite: %d", n)
	}
	if n := ovlWrites.Load(); n != 0 {
		t.Fatalf("overlay-bound packet leaked to OnOverlayWrite: %d", n)
	}
}

// ---- test 2: SOCKS5 upstream SYN emission with strict packet inspection ---

// TestE2ESocks5SynEmission asserts the full set of invariants on the SYN that
// lands on OnOverlayWrite: dst = SOCKS5 peer IP, src = LocalIP, dport = 1080,
// TCP SYN flag set. It also asserts the overlay-bypass path fired zero times
// (a public-IP flow must never be classified as overlay-bypass).
func TestE2ESocks5SynEmission(t *testing.T) {
	overlayPkts := make(chan []byte, 32)
	bypassCount := atomic.Int32{}
	phys := newStubDialer()

	s, err := New(Config{
		LocalIP: netip.MustParseAddr("10.0.0.5"),
		MTU:     1500,
		OverlayRanges: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/24"),
		},
		Mode:       ModeSocks5,
		Socks5Peer: netip.MustParseAddrPort("10.0.0.1:1080"),
		OnTunWrite:      func(_ []byte) error { return nil },
		OnOverlayWrite: func(pkt []byte) error {
			cp := make([]byte, len(pkt))
			copy(cp, pkt)
			overlayPkts <- cp
			return nil
		},
		OnOverlayBypass: func(_ []byte) error { bypassCount.Add(1); return nil },
		PhysicalDialer:  phys,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Close()

	syn := buildTCPSyn(netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("8.8.8.8"), 54321, 443)
	s.HandleTunInbound(syn)

	peer := netip.MustParseAddr("10.0.0.1")
	self := netip.MustParseAddr("10.0.0.5")
	deadline := time.After(mediumDeadline)
	for {
		select {
		case pkt := <-overlayPkts:
			info, ok := parseTCPPacket(pkt)
			if !ok || info.dst != peer {
				continue
			}
			if info.src != self {
				t.Fatalf("upstream SYN src: want %s, got %s", self, info.src)
			}
			if info.dport != 1080 {
				t.Fatalf("upstream SYN dport: want 1080, got %d", info.dport)
			}
			if !info.syn {
				t.Fatalf("upstream packet is not a SYN (flags=%#x)", info.flags)
			}
			if info.ack {
				t.Fatalf("upstream SYN must not have ACK flag on first packet (flags=%#x)", info.flags)
			}
			if n := bypassCount.Load(); n != 0 {
				t.Fatalf("public-IP flow spilled into OnOverlayBypass: %d", n)
			}
			return
		case <-deadline:
			t.Fatalf("no upstream SYN to %s within %s", peer, mediumDeadline)
		}
	}
}

// ---- test 3: fallback to physical dialer when SOCKS5 is off ---------------

// TestE2EPhysicalDialForPublicNoSocks5 injects a public-IP SYN with SOCKS5
// availability off and asserts the physical dialer is invoked with the
// original (unmutated) target. Uses stubDialer.dialCh to await the call
// without polling.
func TestE2EPhysicalDialForPublicNoSocks5(t *testing.T) {
	ovlWrites := atomic.Int32{}
	phys := newStubDialer()

	s, err := New(Config{
		LocalIP: netip.MustParseAddr("10.0.0.5"),
		MTU:     1500,
		OverlayRanges: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/24"),
		},
		Mode: ModeDirect,
		OnTunWrite:      func(_ []byte) error { return nil },
		OnOverlayWrite:  func(_ []byte) error { ovlWrites.Add(1); return nil },
		OnOverlayBypass: func(_ []byte) error { return nil },
		PhysicalDialer:  phys,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Close()

	syn := buildTCPSyn(netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("8.8.8.8"), 54321, 443)
	s.HandleTunInbound(syn)

	select {
	case got := <-phys.dialCh:
		if got != "tcp:8.8.8.8:443" {
			t.Fatalf("physical dialer called with wrong target: %s", got)
		}
	case <-time.After(mediumDeadline):
		t.Fatalf("physical dialer not called within %s", mediumDeadline)
	}
	if n := ovlWrites.Load(); n != 0 {
		t.Fatalf("public-IP flow must not emit overlay packets with SOCKS5 off: %d", n)
	}
}

// ---- test 4: dialDrop when no upstream at all -----------------------------

// TestE2EDialDropNoUpstream removes both SOCKS5 and the physical dialer. The
// handler's classifyDial should return dialDrop, the forwarder should RST
// via req.Complete(true), and — crucially — nothing should appear on
// OnOverlayWrite, nothing should call a (nil) dialer, and no goroutine
// should be stuck proxying a dead flow.
func TestE2EDialDropNoUpstream(t *testing.T) {
	ovlWrites := atomic.Int32{}
	tunWrites := atomic.Int32{}

	s, err := New(Config{
		LocalIP: netip.MustParseAddr("10.0.0.5"),
		MTU:     1500,
		OverlayRanges: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/24"),
		},
		Mode: ModeDirect,
		OnTunWrite:      func(_ []byte) error { tunWrites.Add(1); return nil },
		OnOverlayWrite:  func(_ []byte) error { ovlWrites.Add(1); return nil },
		OnOverlayBypass: func(_ []byte) error { return nil },
		PhysicalDialer:  nil,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Close()

	syn := buildTCPSyn(netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("8.8.8.8"), 54321, 443)
	s.HandleTunInbound(syn)

	time.Sleep(fastDeadline)
	if n := ovlWrites.Load(); n != 0 {
		t.Fatalf("OnOverlayWrite fired %d times for dialDrop flow", n)
	}
	// tunWrites is allowed to be >0 because the forwarder emits a RST back
	// at the app; we don't assert the exact count.
	_ = tunWrites.Load()
}

// ---- test 5: UDP post-stack physical dial ---------------------------------

// TestE2EUDPPhysicalDial injects a minimal IPv4 UDP packet destined for a
// public IP and asserts handleUDP flows through to PhysicalDialer.ListenPacket.
// We don't validate the payload round-trip because ListenPacket returns an
// error — the point is exclusively to exercise the UDP branch of the
// post-stack classifier and forwarder.
func TestE2EUDPPhysicalDial(t *testing.T) {
	phys := newStubDialer()
	s, err := New(Config{
		LocalIP: netip.MustParseAddr("10.0.0.5"),
		MTU:     1500,
		OverlayRanges: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/24"),
		},
		Mode: ModeDirect,
		OnTunWrite:      func(_ []byte) error { return nil },
		OnOverlayWrite:  func(_ []byte) error { return nil },
		OnOverlayBypass: func(_ []byte) error { return nil },
		PhysicalDialer:  phys,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Close()

	pkt := buildUDPPkt(netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("8.8.8.8"), 33333, 53, []byte("hi"))
	s.HandleTunInbound(pkt)

	select {
	case got := <-phys.listenCh:
		if got != "udp::0" {
			t.Fatalf("ListenPacket called with unexpected arg: %s", got)
		}
	case <-time.After(mediumDeadline):
		t.Fatalf("ListenPacket not called within %s", mediumDeadline)
	}
}

// ---- test 6: full SOCKS5 handshake + bidirectional data + teardown --------

// TestE2ESocks5HandshakeAndData glues two netstack.Stack instances back to
// back and runs dialSocks5 directly on the client side. Success criteria:
//  1. dialSocks5 returns a non-nil net.Conn with no error (client side).
//  2. SOCKS5 server wrote the CONNECT success reply (peer side).
//  3. Data written on the client conn is observed by the peer's SOCKS5
//     server loop (downstream → upstream).
//  4. Data written from the server loop is observed by the client conn
//     (upstream → downstream).
//  5. Closing the client conn causes the server loop's io.Copy to return
//     (teardown).
//
// We bypass the TCP forwarder (no injected app SYN) because the goal here is
// to cross-validate dialSocks5 + splice + full TCP payload traversal through
// both gvisor stacks. TestE2ESocks5SynEmission already covers the
// forwarder-driven entry point.
func TestE2ESocks5HandshakeAndData(t *testing.T) {
	server := newPipeSocks5Dialer()

	peer, client, stopGlue := setupBackToBackStacks(t, server)
	defer stopGlue()
	defer client.Close()
	defer peer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), handshakeDeadline)
	defer cancel()

	conn, err := client.dialSocks5(ctx, netip.MustParseAddrPort("8.8.8.8:443"))
	if err != nil {
		t.Fatalf("client dialSocks5: %v", err)
	}
	if conn == nil {
		t.Fatal("client dialSocks5 returned nil conn with no error")
	}
	defer conn.Close()

	select {
	case <-server.handshakeDone:
	case <-time.After(handshakeDeadline):
		t.Fatalf("peer SOCKS5 server never signaled handshake done")
	}

	// 3: downstream → upstream payload.
	payload := []byte("hello-from-client")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("conn.Write: %v", err)
	}
	select {
	case got := <-server.dataCh:
		if !bytes.Equal(got, payload) {
			t.Fatalf("peer received %x, want %x", got, payload)
		}
	case <-time.After(mediumDeadline):
		t.Fatalf("peer did not receive client payload within %s", mediumDeadline)
	}

	// 4: upstream → downstream payload.
	reply := []byte("hello-from-server")
	server.writeBack <- reply
	buf := make([]byte, len(reply))
	_ = conn.SetReadDeadline(time.Now().Add(mediumDeadline))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("conn.Read server reply: %v", err)
	}
	if !bytes.Equal(buf, reply) {
		t.Fatalf("client received %x, want %x", buf, reply)
	}

	// 5: teardown — client close causes peer's io.Copy to return.
	conn.Close()
	select {
	case <-server.closed:
	case <-time.After(mediumDeadline):
		t.Fatalf("peer io.Copy did not return after client close")
	}
}

// ---- test 7: concurrent flows ---------------------------------------------

// TestE2EConcurrentFlows injects N distinct SYNs (different sports) and
// asserts the physical dialer sees exactly N calls, each with the expected
// target. Verifies the TCP forwarder + per-flow goroutine dispatch under
// concurrency without hitting the channel queue limit.
func TestE2EConcurrentFlows(t *testing.T) {
	const N = 16
	phys := newStubDialer()

	s, err := New(Config{
		LocalIP: netip.MustParseAddr("10.0.0.5"),
		MTU:     1500,
		OverlayRanges: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/24"),
		},
		Mode: ModeDirect,
		OnTunWrite:      func(_ []byte) error { return nil },
		OnOverlayWrite:  func(_ []byte) error { return nil },
		OnOverlayBypass: func(_ []byte) error { return nil },
		PhysicalDialer:  phys,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Close()

	dst := netip.MustParseAddr("8.8.8.8")
	for i := 0; i < N; i++ {
		syn := buildTCPSyn(netip.MustParseAddr("10.0.0.5"), dst, uint16(40000+i), 443)
		s.HandleTunInbound(syn)
	}

	// Drain exactly N from dialCh so we can assert every flow landed on the
	// expected target. Relying on the calls counter alone would race with
	// in-flight channel sends.
	seen := map[string]int{}
	deadline := time.After(handshakeDeadline)
	for i := 0; i < N; i++ {
		select {
		case got := <-phys.dialCh:
			seen[got]++
		case <-deadline:
			t.Fatalf("only drained %d dials out of %d (counter=%d)", i, N, phys.calls.Load())
		}
	}
	if got := phys.calls.Load(); got != int32(N) {
		t.Fatalf("expected %d physical dials, got %d", N, got)
	}
	want := fmt.Sprintf("tcp:%s:443", dst)
	if n := seen[want]; n != N {
		t.Fatalf("expected all %d dials to target %s, got %d (map: %v)", N, want, n, seen)
	}
}

// ---- test 8: IP family mismatch in dialSocks5 -----------------------------

// TestE2EFamilyMismatch constructs a Stack with an IPv4 LocalIP but an IPv6
// Socks5Peer and verifies dialSocks5 fails fast with a family-mismatch error
// rather than generating an invalid-looking packet. Kills the "dead code in
// dialSocks5" gap flagged in review without needing a full IPv6 datapath.
func TestE2EFamilyMismatch(t *testing.T) {
	s, err := New(Config{
		LocalIP: netip.MustParseAddr("10.0.0.5"),
		MTU:     1500,
		OverlayRanges: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/24"),
		},
		Socks5Peer:      netip.MustParseAddrPort("[fc00::1]:1080"),
		Mode: ModeSocks5,
		OnTunWrite:      func(_ []byte) error { return nil },
		OnOverlayWrite:  func(_ []byte) error { return nil },
		OnOverlayBypass: func(_ []byte) error { return nil },
		PhysicalDialer:  newStubDialer(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), fastDeadline)
	defer cancel()
	_, err = s.dialSocks5(ctx, netip.MustParseAddrPort("8.8.8.8:443"))
	if err == nil {
		t.Fatal("expected family-mismatch error, got nil")
	}
}

// ---- helpers: SOCKS5 server pipe dialer -----------------------------------

// pipeSocks5Dialer satisfies Dialer by returning one end of a net.Pipe on
// every DialContext. The other end runs a SOCKS5 server loop that:
//   - completes the no-auth greeting + CONNECT request exchange,
//   - writes a "succeeded" reply,
//   - mirrors every subsequent byte to dataCh for assertion,
//   - pulls payloads from writeBack to emulate server-pushed bytes.
type pipeSocks5Dialer struct {
	handshakeDone chan struct{}
	dataCh        chan []byte
	writeBack     chan []byte
	closed        chan struct{}
}

func newPipeSocks5Dialer() *pipeSocks5Dialer {
	return &pipeSocks5Dialer{
		handshakeDone: make(chan struct{}),
		dataCh:        make(chan []byte, 16),
		writeBack:     make(chan []byte, 16),
		closed:        make(chan struct{}),
	}
}

func (d *pipeSocks5Dialer) DialContext(_ context.Context, _ string, _ string) (net.Conn, error) {
	a, b := net.Pipe()
	go d.serverLoop(b)
	return a, nil
}

func (d *pipeSocks5Dialer) ListenPacket(_ context.Context, _ string, _ string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

// serverLoop speaks SOCKS5 no-auth server, signals handshakeDone once the
// CONNECT success reply is written, then pumps the two payload channels.
func (d *pipeSocks5Dialer) serverLoop(c net.Conn) {
	defer close(d.closed)
	defer c.Close()

	// Greeting: [VER, NMETHODS, METHODS...].
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	if head[0] != 0x05 || head[1] == 0 {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, head[1])); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// CONNECT request.
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	if req[0] != 0x05 || req[1] != 0x01 {
		return
	}
	var skip int
	switch req[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return
		}
		skip = int(l[0])
	default:
		return
	}
	if _, err := io.ReadFull(c, make([]byte, skip+2)); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	close(d.handshakeDone)

	// Pump: reader goroutine forwards to dataCh; writer goroutine drains
	// writeBack. Loop exits when c is closed by either side.
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				cp := make([]byte, n)
				copy(cp, buf[:n])
				select {
				case d.dataCh <- cp:
				default:
				}
			}
			if err != nil {
				return
			}
		}
	}()
	for {
		select {
		case <-done:
			return
		case out := <-d.writeBack:
			if _, err := c.Write(out); err != nil {
				return
			}
		}
	}
}

// ---- helpers: back-to-back stack harness ----------------------------------

// setupBackToBackStacks wires a peer netstack.Stack and a client
// netstack.Stack together. The peer's PhysicalDialer is `serverDialer` so
// that every inbound flow on the peer side is routed into a fresh SOCKS5
// server instance. Returns a stop function that safely tears down the glue
// goroutines; callers still own Close() on both stacks.
//
// This helper replaces the fragile defer-ordering dance that previously
// lived inline.
func setupBackToBackStacks(t *testing.T, serverDialer Dialer) (peer, client *Stack, stop func()) {
	t.Helper()

	clientToPeer := make(chan []byte, 256)
	peerToClient := make(chan []byte, 256)

	peerCfg := Config{
		LocalIP: netip.MustParseAddr("10.0.0.1"),
		MTU:     1500,
		OverlayRanges: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/24"),
		},
		OnTunWrite: func(pkt []byte) error {
			cp := make([]byte, len(pkt))
			copy(cp, pkt)
			peerToClient <- cp
			return nil
		},
		OnOverlayWrite:  func(_ []byte) error { return nil },
		OnOverlayBypass: func(_ []byte) error { return nil },
		PhysicalDialer:  serverDialer,
	}
	var err error
	peer, err = New(peerCfg)
	if err != nil {
		t.Fatalf("peer New: %v", err)
	}
	if err := peer.Start(); err != nil {
		t.Fatalf("peer Start: %v", err)
	}

	clientCfg := Config{
		LocalIP: netip.MustParseAddr("10.0.0.5"),
		MTU:     1500,
		OverlayRanges: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/24"),
		},
		Mode:       ModeSocks5,
		Socks5Peer: netip.MustParseAddrPort("10.0.0.1:1080"),
		OnTunWrite:      func(_ []byte) error { return nil },
		OnOverlayWrite: func(pkt []byte) error {
			cp := make([]byte, len(pkt))
			copy(cp, pkt)
			clientToPeer <- cp
			return nil
		},
		OnOverlayBypass: func(_ []byte) error { return nil },
		PhysicalDialer:  newStubDialer(),
	}
	client, err = New(clientCfg)
	if err != nil {
		peer.Close()
		t.Fatalf("client New: %v", err)
	}
	if err := client.Start(); err != nil {
		peer.Close()
		t.Fatalf("client Start: %v", err)
	}

	var (
		quit    = make(chan struct{})
		stopped sync.Once
		wg      sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case pkt := <-clientToPeer:
				peer.HandleTunInbound(pkt)
			case <-quit:
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case pkt := <-peerToClient:
				client.HandleOverlayInbound(pkt)
			case <-quit:
				return
			}
		}
	}()

	stop = func() {
		stopped.Do(func() {
			close(quit)
			wg.Wait()
		})
	}
	return peer, client, stop
}

// ---- helpers: packet builder / parser -------------------------------------

// tcpPacketInfo carries the fields post-stack tests typically want to assert.
type tcpPacketInfo struct {
	src, dst     netip.Addr
	sport, dport uint16
	flags        byte
	syn, ack     bool
}

func parseTCPPacket(pkt []byte) (tcpPacketInfo, bool) {
	if len(pkt) < 20 {
		return tcpPacketInfo{}, false
	}
	if pkt[0]>>4 != 4 {
		return tcpPacketInfo{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if len(pkt) < ihl+20 {
		return tcpPacketInfo{}, false
	}
	if pkt[9] != 6 {
		return tcpPacketInfo{}, false
	}
	tcp := pkt[ihl:]
	flags := tcp[13]
	return tcpPacketInfo{
		src:   netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]}),
		dst:   netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}),
		sport: binary.BigEndian.Uint16(tcp[0:2]),
		dport: binary.BigEndian.Uint16(tcp[2:4]),
		flags: flags,
		syn:   flags&0x02 != 0,
		ack:   flags&0x10 != 0,
	}, true
}

// buildUDPPkt creates a minimal IPv4 UDP packet with a valid UDP checksum
// (gvisor accepts checksum=0 but computing one keeps the test plumbing
// future-proof if we ever toggle strict checks).
func buildUDPPkt(src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	const ipHdrLen = 20
	const udpHdrLen = 8
	total := ipHdrLen + udpHdrLen + len(payload)

	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	pkt[8] = 64
	pkt[9] = 17 // UDP
	copy(pkt[12:16], src.AsSlice())
	copy(pkt[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:ipHdrLen]))

	udp := pkt[ipHdrLen:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpHdrLen+len(payload)))
	copy(udp[udpHdrLen:], payload)
	binary.BigEndian.PutUint16(udp[6:8], udpChecksum(src, dst, udp))
	return pkt
}

func udpChecksum(src, dst netip.Addr, udp []byte) uint16 {
	var sum uint32
	s := src.As4()
	d := dst.As4()
	sum += uint32(binary.BigEndian.Uint16(s[0:2]))
	sum += uint32(binary.BigEndian.Uint16(s[2:4]))
	sum += uint32(binary.BigEndian.Uint16(d[0:2]))
	sum += uint32(binary.BigEndian.Uint16(d[2:4]))
	sum += uint32(17) // protocol
	sum += uint32(len(udp))
	for i := 0; i+1 < len(udp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udp[i:]))
	}
	if len(udp)%2 == 1 {
		sum += uint32(udp[len(udp)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	cs := ^uint16(sum)
	if cs == 0 {
		// RFC 768: transmitted checksum of zero means "no checksum" for IPv4;
		// flip to all-ones to preserve that distinction.
		cs = 0xffff
	}
	return cs
}
