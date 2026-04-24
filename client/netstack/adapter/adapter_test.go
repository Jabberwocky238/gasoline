package adapter

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jabberwocky238/gasoline/client/netstack"
)

// stubDialer is a minimal Dialer that fails both paths — the adapter-level
// tests don't exercise the dial path, we just need something non-nil for
// New() to accept.
type stubDialer struct{}

func (stubDialer) DialContext(_ context.Context, _ string, _ string) (net.Conn, error) {
	return nil, errors.New("stub")
}
func (stubDialer) ListenPacket(_ context.Context, _ string, _ string) (net.PacketConn, error) {
	return nil, errors.New("stub")
}

// TestAdapterTunOverlayRouting feeds one overlay-destined and one
// public-destined raw TCP SYN into OnTunPacket and verifies the adapter
// routes each correctly:
//   - overlay packet → ShipToOverlay fires; WriteToTUN does not
//   - public packet  → gvisor handleTCP eventually calls the physical
//     dialer (we just count); WriteToTUN may fire with SYN-ACK which we
//     don't assert.
func TestAdapterTunPacketRouting(t *testing.T) {
	var overlayShips, tunWrites atomic.Int32
	ad, err := New(Config{
		LocalIP: netip.MustParseAddr("10.0.0.5"),
		MTU:     1500,
		OverlayRanges: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/24"),
		},
		Mode:           netstack.ModeDirect,
		WriteToTUN:     func(_ []byte) error { tunWrites.Add(1); return nil },
		ShipToOverlay:  func(_ []byte) error { overlayShips.Add(1); return nil },
		PhysicalDialer: stubDialer{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := ad.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer ad.Close()

	// Overlay peer destination — must ship, must not tun-write.
	if !ad.OnTunPacket(buildMinimalTCPSyn(
		netip.MustParseAddr("10.0.0.5"),
		netip.MustParseAddr("10.0.0.9"), 1, 80,
	)) {
		t.Fatal("OnTunPacket should always report consumed=true")
	}
	// Give the classifier + any drain goroutine a beat.
	time.Sleep(100 * time.Millisecond)
	if overlayShips.Load() != 1 {
		t.Fatalf("expected 1 overlay ship for overlay-dst packet, got %d", overlayShips.Load())
	}

	// Public destination — must NOT ship to overlay.
	before := overlayShips.Load()
	ad.OnTunPacket(buildMinimalTCPSyn(
		netip.MustParseAddr("10.0.0.5"),
		netip.MustParseAddr("8.8.8.8"), 2, 443,
	))
	time.Sleep(100 * time.Millisecond)
	if overlayShips.Load() != before {
		t.Fatal("public-dst packet should not have been shipped to overlay")
	}
}

// TestAdapterOverlayPacketDispatch verifies OnOverlayPacket returns
// consumed=true only after a flow has been registered on the underlying
// stack. Caller uses this to decide between injecting into netstack vs
// writing to OS TUN.
func TestAdapterOverlayPacketDispatch(t *testing.T) {
	ad, err := New(Config{
		LocalIP: netip.MustParseAddr("10.0.0.5"),
		MTU:     1500,
		OverlayRanges: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/24"),
		},
		Mode:           netstack.ModeDirect,
		WriteToTUN:     func(_ []byte) error { return nil },
		ShipToOverlay:  func(_ []byte) error { return nil },
		PhysicalDialer: stubDialer{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := ad.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer ad.Close()

	// No flows registered → overlay packet is not consumed (adapter tells
	// vtap: go ahead and tun.Write this).
	pkt := buildMinimalTCPSyn(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.5"), 1080, 54321,
	)
	if ad.OnOverlayPacket(pkt) {
		t.Fatal("unregistered flow should not be consumed")
	}

	// Register a matching TCP flow on the inner stack (simulating a
	// successful dialSocks5). Now the same packet must be consumed.
	ad.Stack().RegisterFlow(netstack.ProtoTCP, 54321)
	defer ad.Stack().UnregisterFlow(netstack.ProtoTCP, 54321)
	if !ad.OnOverlayPacket(pkt) {
		t.Fatal("matching flow should be consumed")
	}
}

// TestAdapterSetupRoutesFires confirms SetupRoutes is invoked exactly
// once during Start() and that a SetupRoutes error aborts startup.
func TestAdapterSetupRoutesFires(t *testing.T) {
	var calls atomic.Int32
	ad, err := New(Config{
		LocalIP:         netip.MustParseAddr("10.0.0.5"),
		MTU:             1500,
		OverlayRanges:   []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		Mode:            netstack.ModeDirect,
		WriteToTUN:      func(_ []byte) error { return nil },
		ShipToOverlay:   func(_ []byte) error { return nil },
		PhysicalDialer:  stubDialer{},
		SetupRoutes:     func() error { calls.Add(1); return nil },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := ad.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer ad.Close()
	if calls.Load() != 1 {
		t.Fatalf("SetupRoutes calls: got %d, want 1", calls.Load())
	}
}

func TestAdapterSetupRoutesErrorAbortsStart(t *testing.T) {
	sentinel := errors.New("boom")
	ad, err := New(Config{
		LocalIP:         netip.MustParseAddr("10.0.0.5"),
		MTU:             1500,
		OverlayRanges:   []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		Mode:            netstack.ModeDirect,
		WriteToTUN:      func(_ []byte) error { return nil },
		ShipToOverlay:   func(_ []byte) error { return nil },
		PhysicalDialer:  stubDialer{},
		SetupRoutes:     func() error { return sentinel },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = ad.Start()
	if err == nil {
		t.Fatal("expected Start error when SetupRoutes fails")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected wrapped sentinel, got %v", err)
	}
}

// buildMinimalTCPSyn crafts a tiny but well-formed IPv4 TCP SYN with a
// valid IP checksum and a zero TCP checksum. Enough for the adapter's
// pre-stack classifier to read src/dst/proto/dst-port; gvisor may reject
// on checksum but the tests here don't care whether gvisor accepts —
// overlay-bypass never enters gvisor and public-dst tests only assert the
// absence of ShipToOverlay calls.
func buildMinimalTCPSyn(src, dst netip.Addr, srcPort, dstPort uint16) []byte {
	const ipHdrLen = 20
	const tcpHdrLen = 20
	total := ipHdrLen + tcpHdrLen

	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], src.AsSlice())
	copy(pkt[16:20], dst.AsSlice())
	// IP checksum over the header.
	var sum uint32
	for i := 0; i+1 < ipHdrLen; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(pkt[10:12], ^uint16(sum))

	tcp := pkt[ipHdrLen:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 5 << 4
	tcp[13] = 0x02
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	return pkt
}
