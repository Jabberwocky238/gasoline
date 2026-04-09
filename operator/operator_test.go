package operator

import (
	"bytes"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/jabberwocky238/gasoline/common"

)

// mockConn is a fake transport.Conn for testing.
// WritePacket stores packets; ReadPacket feeds from an injected channel.
type mockConn struct {
	mu       sync.Mutex
	incoming chan []byte // packets to be read by the operator
	received [][]byte   // packets written by the operator (delivered to this "client")
	addr     string
}

func newMockConn(addr string) *mockConn {
	return &mockConn{
		incoming: make(chan []byte, 64),
		addr:     addr,
	}
}

func (c *mockConn) ReadPacket(buf []byte) (int, error) {
	pkt, ok := <-c.incoming
	if !ok {
		return 0, fmt.Errorf("mock conn closed")
	}
	return copy(buf, pkt), nil
}

func (c *mockConn) WritePacket(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	c.received = append(c.received, cp)
	return nil
}

func (c *mockConn) Close() error {
	select {
	case <-c.incoming: // already closed
	default:
		close(c.incoming)
	}
	return nil
}

func (c *mockConn) RemoteAddr() string { return c.addr }

func (c *mockConn) getReceived() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.received))
	copy(out, c.received)
	return out
}

func startTestOperator(t *testing.T, uuid [16]byte) *Operator {
	t.Helper()
	cfg := &common.OperatorConfig{
		UUID:         &uuid,
		OpListenAddr: "127.0.0.1:0",
	}
	op, err := New(cfg)
	if err != nil {
		t.Fatalf("new operator %x: %v", uuid, err)
	}
	if err := op.Start(); err != nil {
		t.Fatalf("start operator %x: %v", uuid, err)
	}
	// Set external addr to the actual bound address
	op.Ctrl.SetExternalAddr(op.GRPCAddr())
	return op
}

func TestRegister(t *testing.T) {
	uuidA := [16]byte{0x01}
	uuidB := [16]byte{0x02}

	opA := startTestOperator(t, uuidA)
	defer opA.Close()
	opB := startTestOperator(t, uuidB)
	defer opB.Close()

	if err := opA.Ctrl.DialOperator(opB.GRPCAddr()); err != nil {
		t.Fatalf("A dial B: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if opA.ConnectedOperators() >= 1 && opB.ConnectedOperators() >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if opA.ConnectedOperators() < 1 {
		t.Fatalf("opA expected >=1 peer, got %d", opA.ConnectedOperators())
	}
	if _, ok := opA.Ctrl.Registry.GetOperator(uuidB); !ok {
		t.Fatal("opA registry missing B")
	}
	if _, ok := opB.Ctrl.Registry.GetOperator(uuidA); !ok {
		t.Fatal("opB registry missing A")
	}
	t.Logf("Register OK")
}

func TestPing(t *testing.T) {
	uuidA := [16]byte{0xAA}
	uuidB := [16]byte{0xBB}

	opA := startTestOperator(t, uuidA)
	defer opA.Close()
	opB := startTestOperator(t, uuidB)
	defer opB.Close()

	if err := opA.Ctrl.DialOperator(opB.GRPCAddr()); err != nil {
		t.Fatalf("dial: %v", err)
	}

	if err := opA.Ctrl.PingOperator(uuidB); err != nil {
		t.Fatalf("ping: %v", err)
	}

	info, ok := opA.Ctrl.Registry.GetOperator(uuidB)
	if !ok {
		t.Fatal("B not in registry")
	}
	if info.LastPing.IsZero() {
		t.Fatal("LastPing not set")
	}
	t.Logf("Ping OK: RTT=%v", info.PingCost)
}

func TestAutoDiscover(t *testing.T) {
	uuidA := [16]byte{0x0A}
	uuidB := [16]byte{0x0B}
	uuidC := [16]byte{0x0C}

	opA := startTestOperator(t, uuidA)
	defer opA.Close()
	opB := startTestOperator(t, uuidB)
	defer opB.Close()

	if err := opA.Ctrl.DialOperator(opB.GRPCAddr()); err != nil {
		t.Fatalf("A dial B: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	cfgC := &common.OperatorConfig{
		UUID:           &uuidC,
		OpListenAddr:   "127.0.0.1:0",
		OpExternalAddr: "placeholder",
		DiscoverAddrs:  []string{opA.GRPCAddr()},
	}
	opC, err := New(cfgC)
	if err != nil {
		t.Fatalf("new C: %v", err)
	}
	if err := opC.Start(); err != nil {
		t.Fatalf("start C: %v", err)
	}
	defer opC.Close()
	opC.Ctrl.SetExternalAddr(opC.GRPCAddr())

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if opC.ConnectedOperators() >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if opC.ConnectedOperators() < 2 {
		t.Fatalf("opC expected >=2 peers, got %d", opC.ConnectedOperators())
	}
	t.Logf("AutoDiscover OK: C found %d peers", opC.ConnectedOperators())
}

func TestSessionSyncAndRevoke(t *testing.T) {
	uuidA := [16]byte{0x10}
	uuidB := [16]byte{0x20}

	opA := startTestOperator(t, uuidA)
	defer opA.Close()
	opB := startTestOperator(t, uuidB)
	defer opB.Close()

	if err := opA.Ctrl.DialOperator(opB.GRPCAddr()); err != nil {
		t.Fatalf("dial: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	sessionID := [16]byte{0xDE, 0xAD}
	vnetID := [16]byte{0x00, 0xC8}
	ip := netip.MustParseAddr("10.0.0.5")

	opA.Ctrl.BroadcastSessionSync(sessionID, vnetID, ip)
	time.Sleep(100 * time.Millisecond)

	vnet, ok := opB.Ctrl.Registry.GetVNet(vnetID)
	if !ok {
		t.Fatal("opB has no VNet after sync")
	}
	info, ok := vnet.Get(sessionID)
	if !ok {
		t.Fatal("opB missing session after sync")
	}
	if info.IP.String() != "10.0.0.5" {
		t.Fatalf("unexpected IP: %s", info.IP)
	}
	t.Logf("SessionSync OK: B sees session at %s", info.IP)

	opA.Ctrl.BroadcastSessionRevoke(sessionID, vnetID)
	time.Sleep(100 * time.Millisecond)

	if _, ok := vnet.Get(sessionID); ok {
		t.Fatal("session still present after revoke")
	}
	t.Logf("SessionRevoke OK")
}

// TestDataForwarding tests the full C→S→S→C data path:
//
//	ClientA(10.0.0.2) on OpA sends a packet destined for ClientB(10.0.0.3) on OpB.
//	OpA can't find 10.0.0.3 locally → forwards via UDP to OpB → OpB delivers to ClientB.
func TestDataForwarding(t *testing.T) {
	uuidA := [16]byte{0xA0}
	uuidB := [16]byte{0xB0}

	opA := startTestOperator(t, uuidA)
	defer opA.Close()
	opB := startTestOperator(t, uuidB)
	defer opB.Close()

	// Connect operators
	if err := opA.Ctrl.DialOperator(opB.GRPCAddr()); err != nil {
		t.Fatalf("A dial B: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if opA.ConnectedOperators() >= 1 && opB.ConnectedOperators() >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	vnetID := [16]byte{0x00, 0xC8} // vnet 200

	// --- Register ClientA on OpA (10.0.0.2) ---
	sessionA := [16]byte{0x01}
	connA := newMockConn("mock://clientA")
	clientA := &ClientPeer{
		Conn:       connA,
		SessionID:  sessionA,
		VNetID:     vnetID,
		OperatorID: uuidA,
		IP:         netip.MustParsePrefix("10.0.0.2/32"),
	}
	clientA.Touch()
	opA.clients.Add(clientA)
	opA.Ctrl.BroadcastSessionSync(sessionA, vnetID, clientA.IP.Addr())
	// Start the read loop so OpA processes packets from ClientA through the real path
	go opA.routineReadFromClient(clientA)
	time.Sleep(50 * time.Millisecond) // let goroutine start

	// --- Register ClientB on OpB (10.0.0.3) ---
	sessionB := [16]byte{0x02}
	connB := newMockConn("mock://clientB")
	clientB := &ClientPeer{
		Conn:       connB,
		SessionID:  sessionB,
		VNetID:     vnetID,
		OperatorID: uuidB,
		IP:         netip.MustParsePrefix("10.0.0.3/32"),
	}
	clientB.Touch()
	opB.clients.Add(clientB)
	opB.Ctrl.BroadcastSessionSync(sessionB, vnetID, clientB.IP.Addr())

	time.Sleep(200 * time.Millisecond)

	// Verify both operators see both sessions in registry
	if _, found := opA.Ctrl.LookupRemoteSession(vnetID, netip.MustParseAddr("10.0.0.3")); !found {
		t.Fatal("OpA doesn't know about ClientB's session")
	}
	if _, found := opB.Ctrl.LookupRemoteSession(vnetID, netip.MustParseAddr("10.0.0.2")); !found {
		t.Fatal("OpB doesn't know about ClientA's session")
	}

	// --- ClientA sends a packet destined for ClientB ---
	// Build raw IP packet, then wrap with data prefix (as a real client would)
	ipPacket := makeIPv4Packet(
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("10.0.0.3"),
		[]byte("hello!!!"),
	)
	// Inject with type prefix: [PacketData][IP packet...]
	wire := make([]byte, 1+len(ipPacket))
	wire[0] = common.PacketData
	copy(wire[1:], ipPacket)
	connA.incoming <- wire

	// Wait for full path: OpA read → strip prefix → forward UDP → OpB recv → add prefix → deliver to ClientB
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(connB.getReceived()) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	received := connB.getReceived()
	if len(received) == 0 {
		t.Fatal("ClientB received no packets")
	}
	// ClientB receives [PacketData][IP packet...] — same as what ClientA sent
	if len(received[0]) < 2 || received[0][0] != common.PacketData {
		t.Fatalf("expected data prefix, got: %x", received[0][:min(len(received[0]), 4)])
	}
	if !bytes.Equal(received[0][1:], ipPacket) {
		t.Fatalf("packet payload mismatch:\n  got:  %x\n  want: %x", received[0][1:], ipPacket)
	}
	t.Logf("Data forwarding OK: C(10.0.0.2)→S(A)→S(B)→C(10.0.0.3), %d bytes", len(ipPacket))
}

// makeIPv4Packet builds a minimal valid IPv4 packet with given src, dst, and payload.
func makeIPv4Packet(src, dst netip.Addr, payload []byte) []byte {
	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45             // version=4, IHL=5 (20 bytes)
	pkt[2] = byte(totalLen >> 8)
	pkt[3] = byte(totalLen)
	pkt[8] = 64               // TTL
	pkt[9] = 17               // protocol = UDP
	s4 := src.As4()
	d4 := dst.As4()
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	copy(pkt[20:], payload)
	return pkt
}
