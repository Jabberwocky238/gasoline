package tests

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jabberwocky238/gasoline/device/client"
	"github.com/jabberwocky238/gasoline/device/cordinator"
	"github.com/jabberwocky238/gasoline/device/operator"
	"github.com/jabberwocky238/gasoline/device/tun"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/protocol/control"
	"github.com/sirupsen/logrus"
)

// TestComplexRouting1 wires 1 cordinator + 2 operators + 2 clients
// (each with a MockTun injected via Client.SetTun) and verifies an IP
// packet sent from mocktun1 reaches mocktun2 across the operator-to-
// operator underlay, with all control-plane setup (cross-operator
// routes) flowing through the cordinator's external HTTP / WS surface.
//
//	  app A         app B
//	   │             ▲
//	   ▼             │
//	  mocktun1     mocktun2          (in-mem, injected via SetTun)
//	   │             ▲
//	   ▼             │
//	  client A ─QUIC─▶ op A ─UDP─▶ op B ◀─QUIC─ client B
//	                  │              │
//	                  └───WS───cord───WS───┘
//	                       (PUT /api/vnet/0/routes)
//
// Client.Dial / Client.SetTun(mocktun) / Client.Start is the real
// production lifecycle, so this test exercises the same data-plane
// pumps (rxLoop, tunReadLoop, keepalive) the binary uses — only the
// kernel TUN is swapped for an in-memory fake whose ring buffer
// captures what would have been delivered to the host stack.
//
// One acknowledged limitation: cord-side WS does not yet broadcast
// PeerJoin/PeerLeave to other operators, so the test wires peer
// underlay endpoints directly via Operator.AddPeer. Cross-operator
// route bindings, however, do flow through cord's REST.
func TestComplexRouting1(t *testing.T) {
	const vni = protocol.VNI_Ty(0)
	const cidr = "10.0.0.0/24"

	// --- 1. Cordinator on an ephemeral port. ---
	cord := cordinator.New("127.0.0.1:0")
	if err := cord.Start(); err != nil {
		t.Fatalf("cord start: %v", err)
	}
	defer cord.Close()
	waitHealthz(t, "http://"+cord.Addr()+"/healthz", 2*time.Second)

	// --- 2. Two operators with disjoint preset CID/prefix bindings. ---
	cidA := protocol.CID_Ty{0, 0, 0, 0, 0, 0, 0, 100}
	cidB := protocol.CID_Ty{0, 0, 0, 0, 0, 0, 0, 101}
	pfxA := netip.MustParsePrefix("10.0.0.100/32")
	pfxB := netip.MustParsePrefix("10.0.0.101/32")
	uuidA := [16]byte{0x11, 0xAA}
	uuidB := [16]byte{0x22, 0xBB}

	opA := buildOpForRouting(t, uuidA, vni, cidr, cidA, pfxA)
	defer opA.Close()
	opB := buildOpForRouting(t, uuidB, vni, cidr, cidB, pfxB)
	defer opB.Close()

	// --- 3. Operator-to-operator peer-table wiring. ---
	apA, err := netip.ParseAddrPort(opA.DataPlaneAddr())
	if err != nil {
		t.Fatalf("parse opA underlay: %v", err)
	}
	apB, err := netip.ParseAddrPort(opB.DataPlaneAddr())
	if err != nil {
		t.Fatalf("parse opB underlay: %v", err)
	}
	opA.AddPeer(uuidB, apB)
	opB.AddPeer(uuidA, apA)

	// --- 4. Both operators dial the cordinator's WS endpoint. ---
	wsURL := "ws://" + cord.Addr() + "/ws"
	connectViaCord(t, opA, wsURL)
	connectViaCord(t, opB, wsURL)

	// --- 5. Publish cross-operator routes through cord's REST. ---
	cordPutRoute(t, cord.Addr(), vni, cidA, pfxA, uuidA)
	cordPutRoute(t, cord.Addr(), vni, cidB, pfxB, uuidB)

	// Give the broadcast a moment to land on both operators' read loops.
	// (No per-operator readiness signal yet; 300ms is comfortably above
	// the in-process loopback round-trip we observe.)
	time.Sleep(300 * time.Millisecond)

	// --- 6. Build two Clients, each pointed at its own operator.
	//        Dial() runs the handshake; SetTun() injects the MockTun;
	//        Start() spins up the real rxLoop / tunReadLoop / keepalive. ---
	clientA, mocktunA := buildClientWithMockTun(t, opA.ClientAddr(), cidA, vni, "mocktun1")
	defer clientA.Close()
	clientB, mocktunB := buildClientWithMockTun(t, opB.ClientAddr(), cidB, vni, "mocktun2")
	defer clientB.Close()

	scA := clientA.SessionContext()
	scB := clientB.SessionContext()
	if scA.IP != pfxA.Addr() {
		t.Fatalf("client A assigned IP %s != preset %s", scA.IP, pfxA.Addr())
	}
	if scB.IP != pfxB.Addr() {
		t.Fatalf("client B assigned IP %s != preset %s", scB.IP, pfxB.Addr())
	}
	t.Logf("client A=%s   client B=%s", scA.IP, scB.IP)

	// Operator-pushed config sanity: each MockTun should now carry the
	// (address, /24) the handshake handed back.
	wantPfxA := netip.PrefixFrom(scA.IP, scA.IPRanges.Bits())
	wantPfxB := netip.PrefixFrom(scB.IP, scB.IPRanges.Bits())
	if got := mocktunA.Options().Address; got != wantPfxA {
		t.Fatalf("mocktun1 address: got %s want %s", got, wantPfxA)
	}
	if got := mocktunB.Options().Address; got != wantPfxB {
		t.Fatalf("mocktun2 address: got %s want %s", got, wantPfxB)
	}

	// --- 7. mocktun1 -> mocktun2. The test injects from "app A";
	//        Client.tunReadLoop pulls it off mocktun1.Read and writes
	//        to connA. opA forwards over the underlay to opB; opB
	//        delivers to connB; Client.rxLoop writes it into
	//        mocktun2.Write, which lands in the capture ring. ---
	payload := []byte("hello-from-mocktun1-over-cord-driven-routing")
	pkt := makeIPv4Packet(scA.IP, scB.IP, payload)

	if err := mocktunA.Inject(pkt); err != nil {
		t.Fatalf("inject into mocktun1: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for mocktunB.ReceivedCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("timeout: no packet captured on mocktun2 within 3s")
		}
		time.Sleep(10 * time.Millisecond)
	}

	got := mocktunB.Received()
	if len(got) != 1 {
		t.Fatalf("mocktun2 captured %d packets, want 1", len(got))
	}
	if len(got[0]) < 20+len(payload) {
		t.Fatalf("mocktun2 packet too short: %d < %d", len(got[0]), 20+len(payload))
	}
	if !bytes.Equal(got[0][20:20+len(payload)], payload) {
		t.Fatalf("mocktun2 payload mismatch:\n got %q\nwant %q",
			got[0][20:20+len(payload)], payload)
	}
	t.Logf("mocktun1 -> mocktun2 delivered %d-byte payload (frame %d bytes) via cord-driven routing",
		len(payload), len(got[0]))
	// mocktun1 should not have captured anything back — A only sent.
	if n := mocktunA.ReceivedCount(); n != 0 {
		t.Fatalf("mocktun1 unexpectedly captured %d packets", n)
	}

	// --- 9. LAN-behind-A scenario. Tell the control plane that A
	//        owns the entire 10.0.1.0/24 prefix (a downstream LAN
	//        sitting behind A's mocktun), then send a packet from
	//        B targeting an IP inside that prefix. opB's LPM must
	//        match 10.0.1.0/24 -> uuidA and ship the packet across
	//        the underlay; opA's LPM must match 10.0.1.0/24 -> cidA
	//        locally so it gets delivered to client A's mocktun.
	lanPfx := netip.MustParsePrefix("10.0.1.0/24")
	cordPutRoute(t, cord.Addr(), vni, cidA, lanPfx, uuidA)
	time.Sleep(300 * time.Millisecond) // broadcast propagation

	mocktunA.ResetReceived()
	mocktunB.ResetReceived()

	lanTarget := netip.MustParseAddr("10.0.1.1")
	lanPayload := []byte("hello-LAN-behind-A")
	lanPkt := makeIPv4Packet(scB.IP, lanTarget, lanPayload)

	if err := mocktunB.Inject(lanPkt); err != nil {
		t.Fatalf("inject into mocktun2: %v", err)
	}

	deadline = time.Now().Add(3 * time.Second)
	for mocktunA.ReceivedCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("timeout: no packet captured on mocktun1 for 10.0.1.1 within 3s")
		}
		time.Sleep(10 * time.Millisecond)
	}

	lanGot := mocktunA.Received()
	if len(lanGot) != 1 {
		t.Fatalf("mocktun1 captured %d LAN packets, want 1", len(lanGot))
	}
	frame := lanGot[0]
	if len(frame) < 20+len(lanPayload) {
		t.Fatalf("mocktun1 LAN packet too short: %d", len(frame))
	}
	// Sanity-check the IP header: dst must be 10.0.1.1, src must be B.
	gotDst := netip.AddrFrom4([4]byte{frame[16], frame[17], frame[18], frame[19]})
	gotSrc := netip.AddrFrom4([4]byte{frame[12], frame[13], frame[14], frame[15]})
	if gotDst != lanTarget {
		t.Fatalf("LAN dst: got %s want %s", gotDst, lanTarget)
	}
	if gotSrc != scB.IP {
		t.Fatalf("LAN src: got %s want %s", gotSrc, scB.IP)
	}
	if !bytes.Equal(frame[20:20+len(lanPayload)], lanPayload) {
		t.Fatalf("LAN payload mismatch:\n got %q\nwant %q",
			frame[20:20+len(lanPayload)], lanPayload)
	}
	t.Logf("B (%s) -> 10.0.1.1 delivered to mocktun1 via LAN-prefix route (frame %d bytes)",
		scB.IP, len(frame))
	if n := mocktunB.ReceivedCount(); n != 0 {
		t.Fatalf("mocktun2 unexpectedly captured %d packets during LAN test", n)
	}
}

// buildClientWithMockTun returns a fully-started client.Client with a
// MockTun injected via SetTun, plus the MockTun for assertions. The
// TUN's MockTunOptions are populated from the handshake result so
// tests can verify operator-pushed config landed.
func buildClientWithMockTun(t *testing.T, endpoint string, cid protocol.CID_Ty, vni protocol.VNI_Ty, tunName string) (*client.Client, *MockTun) {
	t.Helper()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cfg := &client.StaticClientConfig{
		Endpoint:  endpoint,
		Transport: "quic",
		AuthStr:   "noauth",
		VNI:       vni,
		CID:       cid,
		TUNName:   tunName, // non-empty enables tunReadLoop in Start
		LogLevel:  logrus.ErrorLevel,
		Logger:    logger,
	}
	c, err := client.New(cfg)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}

	sc, err := c.Dial()
	if err != nil {
		_ = c.Close()
		t.Fatalf("client.Dial: %v", err)
	}

	// MockTun configured with the operator-assigned (IP, CIDR-bits).
	// We pass it through tun.NewFromSingTun so Client sees the same
	// *tun.Tun type it would have made internally — the mock just
	// replaces the platform backend. UpdateRouteOptions on the
	// wrapped Tun will reach this MockTun, letting tests inspect
	// operator-pushed config updates via Options().
	mtun := NewMockTun(MockTunOptions{
		Name:    tunName,
		Address: netip.PrefixFrom(sc.IP, sc.IPRanges.Bits()),
		MTU:     1400,
	})
	c.SetTun(tun.NewFromSingTun(mtun))

	if err := c.Start(); err != nil {
		_ = c.Close()
		t.Fatalf("client.Start: %v", err)
	}
	return c, mtun
}

// buildOpForRouting boots one operator with a single preset
// (cid -> prefix) binding inside vni. Listeners bind to ephemeral
// loopback ports so multiple operators can coexist in one test.
func buildOpForRouting(t *testing.T, uuid [16]byte, vni protocol.VNI_Ty, cidr string, cid protocol.CID_Ty, pfx netip.Prefix) *operator.Operator {
	t.Helper()
	cfg := &operator.StaticOperatorConfig{
		UUID: &uuid,
		ClientListeners: []operator.ListenerSpec{
			{Transport: "quic", Addr: "127.0.0.1:0"},
		},
		OpListenAddr: "127.0.0.1:0",
		Network: map[protocol.VNI_Ty]operator.StaticOperatorVNetConfig{
			vni: {
				VNI:          vni,
				CIDR:         cidr,
				Auth:         &auth.NoAuthServer{},
				PresetCIDmap: map[protocol.CID_Ty]netip.Prefix{cid: pfx},
			},
		},
		LogLevel: logrus.ErrorLevel,
	}
	op, err := operator.New(cfg)
	if err != nil {
		t.Fatalf("operator.New: %v", err)
	}
	if err := op.Start(); err != nil {
		t.Fatalf("operator.Start: %v", err)
	}
	return op
}

// connectViaCord drives op into a CordinatorConnect through its own
// control-plane dispatcher — the same path a real gasoctl command
// would take, so the test exercises the genuine entry point rather
// than reaching into operator internals.
func connectViaCord(t *testing.T, op *operator.Operator, wsURL string) {
	t.Helper()
	reply := op.NewControllerBase().Consume(&control.CordinatorConnect{Endpoint: wsURL})
	if r, ok := reply.(*control.Reply); ok && !r.OK {
		t.Fatalf("cordinator connect rejected: %s", r.Payload)
	}
}

// cordPutRoute does PUT /api/vnet/{vni}/routes against the cord REST
// surface to install one (cid, prefix, ownerUUID) binding. Cord
// broadcasts a RouteUpsert over WS to every connected operator.
func cordPutRoute(t *testing.T, addr string, vni protocol.VNI_Ty, cid protocol.CID_Ty, pfx netip.Prefix, owner [16]byte) {
	t.Helper()
	body := map[string]string{
		"cid":       cid.FormatCID(),
		"prefix":    pfx.String(),
		"ownerUUID": hex.EncodeToString(owner[:]),
	}
	raw, _ := json.Marshal(body)
	url := fmt.Sprintf("http://%s/api/vnet/%d/routes", addr, uint32(vni))
	req, err := http.NewRequest(http.MethodPut, url, strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("build PUT %s: %v", url, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT %s: %d %s", url, resp.StatusCode, string(msg))
	}
}

// waitHealthz polls cordinator's /healthz until 200 or deadline.
func waitHealthz(t *testing.T, url string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("cordinator healthz never came up at %s", url)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
