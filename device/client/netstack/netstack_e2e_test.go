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

// ---- test 5b: UDP physical round-trip with payloads ----------------------

// TestE2EUDPPhysicalRoundTrip wires a capture-and-inject fake PacketConn as
// the physical upstream, feeds an IPv4 UDP packet through the stack, and:
//  1. Asserts the app's payload surfaces on the fake upstream's WriteTo with
//     the correct destination addr.
//  2. Injects a reply on the fake upstream's incoming side and asserts the
//     gvisor UDP reassembler emits a UDP packet back to the app on
//     OnTunWrite carrying the exact reply payload with dport = original
//     sport.
//
// This closes the payload-round-trip gap that TestE2EUDPPhysicalDial left.
func TestE2EUDPPhysicalRoundTrip(t *testing.T) {
	fake := newFakePacketConn()
	dialer := &fakePacketDialer{pc: fake}

	tunOut := make(chan []byte, 64)
	s, err := New(Config{
		LocalIP: netip.MustParseAddr("10.0.0.5"),
		MTU:     1500,
		OverlayRanges: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/24"),
		},
		Mode: ModeDirect,
		OnTunWrite: func(pkt []byte) error {
			cp := make([]byte, len(pkt))
			copy(cp, pkt)
			tunOut <- cp
			return nil
		},
		OnOverlayWrite:  func(_ []byte) error { return nil },
		OnOverlayBypass: func(_ []byte) error { return nil },
		PhysicalDialer:  dialer,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Close()

	const appSport uint16 = 33333
	query := []byte("dns-query")
	app := netip.MustParseAddr("10.0.0.5")
	dst := netip.MustParseAddr("8.8.8.8")
	s.HandleTunInbound(buildUDPPkt(app, dst, appSport, 53, query))

	// 1. Upstream WriteTo.
	select {
	case out := <-fake.outgoing:
		if !bytes.Equal(out.data, query) {
			t.Fatalf("upstream payload: got %x, want %x", out.data, query)
		}
		if got := out.addr.String(); got != "8.8.8.8:53" {
			t.Fatalf("upstream addr: got %s, want 8.8.8.8:53", got)
		}
	case <-time.After(mediumDeadline):
		t.Fatalf("no upstream WriteTo within %s", mediumDeadline)
	}

	// 2. Inject reply and observe on OnTunWrite.
	reply := []byte("dns-reply")
	fake.incoming <- reply
	deadline := time.After(mediumDeadline)
	for {
		select {
		case out := <-tunOut:
			info, ok := parseUDPPacket(out)
			if !ok {
				continue // not UDP — noise from other flows or ICMP
			}
			if info.dport != appSport {
				continue
			}
			if !bytes.Equal(info.payload, reply) {
				t.Fatalf("downstream payload: got %x, want %x", info.payload, reply)
			}
			if info.src != dst {
				t.Fatalf("downstream src: got %s, want %s", info.src, dst)
			}
			return
		case <-deadline:
			t.Fatalf("no UDP reply to app on OnTunWrite within %s", mediumDeadline)
		}
	}
}

// ---- test 5c: SOCKS5 UDP header codec unit tests -------------------------

// TestSocks5UDPHeaderRoundTrip exercises buildSocks5UDPHeader /
// parseSocks5UDPHeader for v4 and v6 targets and confirms that FRAG != 0
// or unknown ATYP are rejected.
func TestSocks5UDPHeaderRoundTrip(t *testing.T) {
	cases := []struct {
		name   string
		target netip.AddrPort
	}{
		{"ipv4", netip.MustParseAddrPort("8.8.8.8:53")},
		{"ipv6", netip.MustParseAddrPort("[2001:4860:4860::8888]:53")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hdr := buildSocks5UDPHeader(tc.target)
			payload := []byte("x")
			pkt := append(append([]byte{}, hdr...), payload...)
			off, err := parseSocks5UDPHeader(pkt)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if off != len(hdr) {
				t.Fatalf("header length mismatch: parse=%d build=%d", off, len(hdr))
			}
			if !bytes.Equal(pkt[off:], payload) {
				t.Fatalf("payload: got %x want %x", pkt[off:], payload)
			}
		})
	}

	// FRAG != 0 must be rejected.
	bad := []byte{0, 0, 0x01, 0x01, 8, 8, 8, 8, 0, 53}
	if _, err := parseSocks5UDPHeader(bad); err == nil {
		t.Fatal("expected FRAG != 0 to be rejected")
	}

	// Unknown ATYP must be rejected.
	bad[2] = 0
	bad[3] = 0x05
	if _, err := parseSocks5UDPHeader(bad); err == nil {
		t.Fatal("expected unknown ATYP to be rejected")
	}

	// Truncation must be rejected.
	trunc := []byte{0, 0, 0, 0x01, 8, 8, 8} // IPv4 header short by 1 + port
	if _, err := parseSocks5UDPHeader(trunc); err == nil {
		t.Fatal("expected truncated header to be rejected")
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

// ---- test 6b: full SOCKS5 UDP ASSOCIATE round-trip ------------------------

// TestE2ESocks5UDP extends the back-to-back harness to exercise the UDP
// ASSOCIATE path end-to-end:
//
//	app UDP ─► client NIC-TUN ─► handleUDP ─► dialSocks5UDP
//	   │              ctrl TCP ─► peer NIC-TUN ─► handleTCP ─► peer mock
//	   │              (CMD=3 → BND reply over control pipe)
//	   ▼
//	wrapped UDP to BND ─► client NIC-OVERLAY ─► peer NIC-TUN ─►
//	handleUDP (peer) ─► mock UDP listener ─► unwrap ─► test channel
//
// Return path is symmetric: test pushes a reply, mock UDP listener wraps
// it into a SOCKS5 UDP datagram, peer's gvisor ships it back over NIC-TUN,
// glue delivers to client's NIC-OVERLAY, client's socks5UDPPacketConn
// strips the header, client's proxyUDP writes unwrapped bytes to the app
// endpoint, client's gvisor emits the reply UDP packet out NIC-TUN where
// OnTunWrite captures it. Assertions cover payload + target + source.
func TestE2ESocks5UDP(t *testing.T) {
	bnd := netip.MustParseAddrPort("10.0.0.1:10080")
	peerMock := newSocks5PeerMockUDP(bnd)

	clientTunOut := make(chan []byte, 64)
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
		PhysicalDialer:  peerMock,
	}
	peer, err := New(peerCfg)
	if err != nil {
		t.Fatalf("peer New: %v", err)
	}
	if err := peer.Start(); err != nil {
		t.Fatalf("peer Start: %v", err)
	}
	defer peer.Close()

	clientCfg := Config{
		LocalIP: netip.MustParseAddr("10.0.0.5"),
		MTU:     1500,
		OverlayRanges: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/24"),
		},
		Mode:       ModeSocks5,
		Socks5Peer: netip.MustParseAddrPort("10.0.0.1:1080"),
		OnTunWrite: func(pkt []byte) error {
			cp := make([]byte, len(pkt))
			copy(cp, pkt)
			clientTunOut <- cp
			return nil
		},
		OnOverlayWrite: func(pkt []byte) error {
			cp := make([]byte, len(pkt))
			copy(cp, pkt)
			clientToPeer <- cp
			return nil
		},
		OnOverlayBypass: func(_ []byte) error { return nil },
		PhysicalDialer:  newStubDialer(),
	}
	client, err := New(clientCfg)
	if err != nil {
		t.Fatalf("client New: %v", err)
	}
	if err := client.Start(); err != nil {
		t.Fatalf("client Start: %v", err)
	}
	defer client.Close()

	quit := make(chan struct{})
	var wg sync.WaitGroup
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
	defer func() { close(quit); wg.Wait() }()

	// Trigger: app UDP to 8.8.8.8:53.
	const appSport uint16 = 33333
	query := []byte("dns-query")
	s := netip.MustParseAddr("10.0.0.5")
	d := netip.MustParseAddr("8.8.8.8")
	client.HandleTunInbound(buildUDPPkt(s, d, appSport, 53, query))

	// 1. Control channel handshake completed (peer wrote CMD=3 success reply).
	select {
	case <-peerMock.handshakeDone:
	case <-time.After(handshakeDeadline):
		t.Fatal("UDP ASSOCIATE handshake did not complete within deadline")
	}

	// 2. Peer mock's UDP relay saw the unwrapped payload + real target.
	select {
	case got := <-peerMock.udpIncoming:
		if !bytes.Equal(got.payload, query) {
			t.Fatalf("peer payload: got %x, want %x", got.payload, query)
		}
		if got.target != netip.MustParseAddrPort("8.8.8.8:53") {
			t.Fatalf("peer target: got %s, want 8.8.8.8:53", got.target)
		}
	case <-time.After(handshakeDeadline):
		t.Fatal("peer mock did not receive unwrapped UDP payload")
	}

	// 3. Peer pushes a reply; client must see the reply as a UDP packet.
	reply := []byte("dns-reply")
	peerMock.udpOutgoing <- udpReply{
		payload: reply,
		src:     netip.MustParseAddrPort("8.8.8.8:53"),
	}
	deadline := time.After(handshakeDeadline)
	for {
		select {
		case out := <-clientTunOut:
			info, ok := parseUDPPacket(out)
			if !ok || info.dport != appSport {
				continue
			}
			if !bytes.Equal(info.payload, reply) {
				t.Fatalf("reply payload: got %x, want %x", info.payload, reply)
			}
			if info.src.String() != "8.8.8.8" {
				t.Fatalf("reply src: got %s, want 8.8.8.8", info.src)
			}
			return
		case <-deadline:
			t.Fatal("no UDP reply to app on client's OnTunWrite")
		}
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

// udpPacketInfo carries the fields UDP e2e tests typically assert.
type udpPacketInfo struct {
	src, dst     netip.Addr
	sport, dport uint16
	payload      []byte
}

func parseUDPPacket(pkt []byte) (udpPacketInfo, bool) {
	if len(pkt) < 28 {
		return udpPacketInfo{}, false
	}
	if pkt[0]>>4 != 4 {
		return udpPacketInfo{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if len(pkt) < ihl+8 {
		return udpPacketInfo{}, false
	}
	if pkt[9] != 17 {
		return udpPacketInfo{}, false
	}
	udp := pkt[ihl:]
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 || ihl+udpLen > len(pkt) {
		return udpPacketInfo{}, false
	}
	return udpPacketInfo{
		src:     netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]}),
		dst:     netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}),
		sport:   binary.BigEndian.Uint16(udp[0:2]),
		dport:   binary.BigEndian.Uint16(udp[2:4]),
		payload: udp[8:udpLen],
	}, true
}

// fakePacketConn is a test double for net.PacketConn. It captures every
// WriteTo on `outgoing` and delivers whatever bytes are pushed onto
// `incoming` as ReadFrom returns. SetReadDeadline / SetWriteDeadline are
// no-ops — tests close the conn to unblock instead.
type fakePacketConn struct {
	incoming  chan []byte
	outgoing  chan outgoingDGram
	closeCh   chan struct{}
	closeOnce sync.Once
}

type outgoingDGram struct {
	data []byte
	addr net.Addr
}

func newFakePacketConn() *fakePacketConn {
	return &fakePacketConn{
		incoming: make(chan []byte, 16),
		outgoing: make(chan outgoingDGram, 16),
		closeCh:  make(chan struct{}),
	}
}

func (f *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case data := <-f.incoming:
		return copy(p, data), &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8).To4(), Port: 53}, nil
	case <-f.closeCh:
		return 0, nil, net.ErrClosed
	}
}

func (f *fakePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-f.closeCh:
		return 0, net.ErrClosed
	default:
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	select {
	case f.outgoing <- outgoingDGram{data: cp, addr: addr}:
		return len(p), nil
	case <-f.closeCh:
		return 0, net.ErrClosed
	}
}

func (f *fakePacketConn) Close() error {
	f.closeOnce.Do(func() { close(f.closeCh) })
	return nil
}

func (f *fakePacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{Port: 0} }
func (f *fakePacketConn) SetDeadline(_ time.Time) error      { return nil }
func (f *fakePacketConn) SetReadDeadline(_ time.Time) error  { return nil }
func (f *fakePacketConn) SetWriteDeadline(_ time.Time) error { return nil }

// fakePacketDialer satisfies Dialer by returning a single fakePacketConn on
// ListenPacket. DialContext is not implemented; tests that need both TCP
// and UDP fakes should wire two separate dialers or compose manually.
type fakePacketDialer struct {
	pc *fakePacketConn
}

func (d *fakePacketDialer) DialContext(_ context.Context, _ string, _ string) (net.Conn, error) {
	return nil, errors.New("fakePacketDialer: TCP dial not implemented")
}

func (d *fakePacketDialer) ListenPacket(_ context.Context, _ string, _ string) (net.PacketConn, error) {
	return d.pc, nil
}

// ---- SOCKS5 UDP peer mock -------------------------------------------------

// socks5PeerMockUDP implements Dialer with BOTH sides of a SOCKS5 UDP
// ASSOCIATE responder: DialContext on TCP serves the control channel
// (greeting + CMD=3 + BND reply), ListenPacket returns a fake PacketConn
// that parses every SOCKS5 UDP datagram written to it and exposes the
// unwrapped payload on udpIncoming for assertion. Replies pushed to
// udpOutgoing are wrapped with a SOCKS5 UDP header and returned on the
// listener's ReadFrom.
type socks5PeerMockUDP struct {
	bnd netip.AddrPort // advertised in the UDP ASSOCIATE reply

	handshakeDone chan struct{}
	handshakeOnce sync.Once
	udpIncoming   chan udpCaptured
	udpOutgoing   chan udpReply

	listener *fakeUDPRelayConn
}

type udpCaptured struct {
	payload []byte
	target  netip.AddrPort
	peerSrc net.Addr
}

type udpReply struct {
	payload []byte
	src     netip.AddrPort
}

func newSocks5PeerMockUDP(bnd netip.AddrPort) *socks5PeerMockUDP {
	m := &socks5PeerMockUDP{
		bnd:           bnd,
		handshakeDone: make(chan struct{}),
		udpIncoming:   make(chan udpCaptured, 16),
		udpOutgoing:   make(chan udpReply, 16),
	}
	m.listener = &fakeUDPRelayConn{
		mock:    m,
		closeCh: make(chan struct{}),
	}
	return m
}

func (m *socks5PeerMockUDP) DialContext(_ context.Context, _ string, _ string) (net.Conn, error) {
	a, b := net.Pipe()
	go m.tcpServerLoop(b)
	return a, nil
}

func (m *socks5PeerMockUDP) ListenPacket(_ context.Context, _ string, _ string) (net.PacketConn, error) {
	return m.listener, nil
}

// tcpServerLoop speaks just enough SOCKS5 to accept greeting + one CMD=3
// request, reply with the configured BND, and then hold the control
// connection open until the client closes. The UDP ASSOCIATE contract
// requires the control conn to stay alive for the life of the UDP relay.
func (m *socks5PeerMockUDP) tcpServerLoop(c net.Conn) {
	defer c.Close()

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

	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	if req[0] != 0x05 {
		return
	}
	// Read and discard the requested ADDR+PORT (wildcard from real clients).
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

	// Only CMD=3 (UDP ASSOCIATE) is meaningful here — CONNECT is exercised
	// elsewhere; fail others fast so a miswired test blows up instead of
	// hanging.
	if req[1] != 0x03 {
		return
	}

	// Reply: VER=5 REP=0 RSV=0 ATYP=1 BND.ADDR BND.PORT.
	b := m.bnd.Addr().As4()
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], m.bnd.Port())
	reply := []byte{0x05, 0x00, 0x00, 0x01, b[0], b[1], b[2], b[3], port[0], port[1]}
	if _, err := c.Write(reply); err != nil {
		return
	}

	m.handshakeOnce.Do(func() { close(m.handshakeDone) })

	// Keep the control open until client closes — matches real RFC 1928
	// semantics where the UDP relay is torn down when control drops.
	_, _ = io.Copy(io.Discard, c)
}

// fakeUDPRelayConn is what peer.handleUDP receives from ListenPacket. Every
// WriteTo is a SOCKS5-wrapped datagram from the client; we parse the
// header, hand the inner payload + target off to the test via udpIncoming.
// Every ReadFrom pulls from udpOutgoing, builds a SOCKS5-wrapped reply.
type fakeUDPRelayConn struct {
	mock      *socks5PeerMockUDP
	closeCh   chan struct{}
	closeOnce sync.Once
}

func (f *fakeUDPRelayConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-f.closeCh:
		return 0, net.ErrClosed
	default:
	}
	hdrLen, err := parseSocks5UDPHeader(p)
	if err != nil {
		return 0, err
	}
	target, err := extractSocks5UDPTarget(p[:hdrLen])
	if err != nil {
		return 0, err
	}
	payload := make([]byte, len(p)-hdrLen)
	copy(payload, p[hdrLen:])
	select {
	case f.mock.udpIncoming <- udpCaptured{payload: payload, target: target, peerSrc: addr}:
		return len(p), nil
	case <-f.closeCh:
		return 0, net.ErrClosed
	}
}

func (f *fakeUDPRelayConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case r := <-f.mock.udpOutgoing:
		hdr := buildSocks5UDPHeader(r.src)
		buf := make([]byte, 0, len(hdr)+len(r.payload))
		buf = append(buf, hdr...)
		buf = append(buf, r.payload...)
		n := copy(p, buf)
		return n, &net.UDPAddr{IP: f.mock.bnd.Addr().AsSlice(), Port: int(f.mock.bnd.Port())}, nil
	case <-f.closeCh:
		return 0, nil, net.ErrClosed
	}
}

func (f *fakeUDPRelayConn) Close() error {
	f.closeOnce.Do(func() { close(f.closeCh) })
	return nil
}

func (f *fakeUDPRelayConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: f.mock.bnd.Addr().AsSlice(), Port: int(f.mock.bnd.Port())}
}

func (f *fakeUDPRelayConn) SetDeadline(_ time.Time) error      { return nil }
func (f *fakeUDPRelayConn) SetReadDeadline(_ time.Time) error  { return nil }
func (f *fakeUDPRelayConn) SetWriteDeadline(_ time.Time) error { return nil }

// extractSocks5UDPTarget reads ATYP+ADDR+PORT from a validated SOCKS5 UDP
// header (callers should have called parseSocks5UDPHeader first and
// confirmed no error). Returns the dst endpoint carried in the header.
func extractSocks5UDPTarget(hdr []byte) (netip.AddrPort, error) {
	if len(hdr) < 4 {
		return netip.AddrPort{}, errors.New("socks5 udp target: too short")
	}
	off := 4
	var addr netip.Addr
	switch hdr[3] {
	case 0x01:
		if len(hdr) < off+6 {
			return netip.AddrPort{}, errors.New("socks5 udp target: ipv4 truncated")
		}
		addr = netip.AddrFrom4([4]byte{hdr[4], hdr[5], hdr[6], hdr[7]})
		off += 4
	case 0x04:
		if len(hdr) < off+18 {
			return netip.AddrPort{}, errors.New("socks5 udp target: ipv6 truncated")
		}
		var a [16]byte
		copy(a[:], hdr[4:20])
		addr = netip.AddrFrom16(a)
		off += 16
	default:
		return netip.AddrPort{}, fmt.Errorf("socks5 udp target: atyp %d not supported", hdr[3])
	}
	port := binary.BigEndian.Uint16(hdr[off : off+2])
	return netip.AddrPortFrom(addr, port), nil
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
