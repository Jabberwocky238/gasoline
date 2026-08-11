package tests

import (
	"fmt"
	"net/netip"
	"os"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jabberwocky238/gasoline/cmd/operator/device"
	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/datacom"
	"github.com/jabberwocky238/gasoline/protocol/noise"
	"github.com/jabberwocky238/gasoline/transport"
	"github.com/sirupsen/logrus"
)

// dataConn wraps a transport.Conn so tests can send/receive plaintext IP
// packets while the wire carries the encrypted data frame the operator now
// expects (SessionTag||Counter||AEAD). It mirrors what the real client does
// in cmd/client/device: seal on write, open on read.
type dataConn struct {
	transport.Conn
	sess *noise.Session
	tag  datacom.SessionTag
}

func newDataConn(inner transport.Conn, sess *noise.Session, sid protocol.SessionID_Ty) *dataConn {
	return &dataConn{Conn: inner, sess: sess, tag: datacom.TagOf(sid)}
}

func (c *dataConn) WritePacket(pkt []byte) error {
	frame, err := datacom.Seal(c.sess, c.tag, pkt)
	if err != nil {
		return err
	}
	return c.Conn.WritePacket(frame)
}

func (c *dataConn) ReadPacket(buf []byte) (int, error) {
	tmp := make([]byte, len(buf)+datacom.HeaderSize+16)
	n, err := c.Conn.ReadPacket(tmp)
	if err != nil {
		return 0, err
	}
	_, ctr, ct, err := datacom.ParseHeader(tmp[:n])
	if err != nil {
		return 0, err
	}
	pt, err := datacom.Open(c.sess, ctr, ct, true)
	if err != nil {
		return 0, err
	}
	return copy(buf, pt), nil
}

const (
	benchVNI      protocol.VNI_Ty = 200
	benchVNetCIDR                 = "10.0.200.0/24"
	benchPayload                  = 1380
	benchRoundSz                  = 10 * 1024 * 1024
	benchRounds                   = 10
)

// benchSetup is the per-test fixture.
type benchSetup struct {
	op   *operator.Operator
	vni  protocol.VNI_Ty
	pfxA netip.Prefix
	pfxB netip.Prefix

	// Noise identities: two client key pairs and the operators' shared server
	// public key. Dialers build transport.ClientIdentity from these. Each
	// client is preset to its fixed IP (pfxA/pfxB) via PresetKeyMap.
	privA     noise.PrivateKey
	pubA      noise.PublicKey
	privB     noise.PrivateKey
	pubB      noise.PublicKey
	serverPub noise.PublicKey
}

// idA / idB return the ClientIdentity for each client against this fixture.
func (s *benchSetup) idA() transport.ClientIdentity {
	return transport.ClientIdentity{Priv: s.privA, Pub: s.pubA, ServerPub: s.serverPub}
}
func (s *benchSetup) idB() transport.ClientIdentity {
	return transport.ClientIdentity{Priv: s.privB, Pub: s.pubB, ServerPub: s.serverPub}
}

// dialAndAssign dials the given dialer, then runs the client-side control-plane
// assignment against the operator (whose accept loop runs the server side).
// Returns the data-plane conn and the assigned SessionContext.
func dialAndAssign(t *testing.T, d transport.Dialer, endpoint string, id transport.ClientIdentity, vni protocol.VNI_Ty) (transport.Conn, *protocol.SessionContext) {
	t.Helper()
	dialed, err := d.Dial(endpoint)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	sc, err := datacom.ClientAssign(dialed.Conn, dialed.Session, vni)
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	return newDataConn(dialed.Conn, dialed.Session, sc.SessionID), sc
}

// startBenchOperators spins up two paired operators: opA owns client A,
// opB owns client B, each knows the other's prefix is reachable through
// the peer. Returns the pair plus the addressing fixtures.
func startBenchOperators(t *testing.T, tp string) (a, b *benchSetup) {
	t.Helper()

	// Two client identities.
	privA, pubA, err := noise.GenerateKey()
	if err != nil {
		t.Fatalf("genkey A: %v", err)
	}
	privB, pubB, err := noise.GenerateKey()
	if err != nil {
		t.Fatalf("genkey B: %v", err)
	}
	pfxA := netip.MustParsePrefix("10.0.200.10/32")
	pfxB := netip.MustParsePrefix("10.0.200.11/32")

	// All operators in a mesh share one static key pair, so a client hands the
	// same ServerPub to any of them.
	serverPriv, serverPub, err := noise.GenerateKey()
	if err != nil {
		t.Fatalf("genkey server: %v", err)
	}
	authKeys := map[noise.PublicKey]struct{}{pubA: {}, pubB: {}}

	// Each operator presets (fixed-IP binds) its own client's pubkey.
	build := func(uuid [16]byte, ownPub noise.PublicKey, ownPfx netip.Prefix) *operator.Operator {
		cfg := &operator.StaticOperatorConfig{
			UUID:       &uuid,
			StaticPriv: serverPriv,
			ClientListeners: []operator.ListenerSpec{
				{Transport: tp, Addr: "127.0.0.1:0"},
			},
			OpListenAddr: "127.0.0.1:0",
			Network: map[protocol.VNI_Ty]operator.StaticOperatorVNetConfig{
				benchVNI: {
					VNI:            benchVNI,
					CIDR:           benchVNetCIDR,
					AuthorizedKeys: authKeys,
					PresetKeyMap:   map[noise.PublicKey]netip.Prefix{ownPub: ownPfx},
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

	uuidA := [16]byte{0xA0}
	uuidB := [16]byte{0xB0}
	opA := build(uuidA, pubA, pfxA)
	opB := build(uuidB, pubB, pfxB)

	apA, errA := netip.ParseAddrPort(opA.DataPlaneAddr())
	apB, errB := netip.ParseAddrPort(opB.DataPlaneAddr())
	if errA != nil || errB != nil {
		t.Fatalf("parse data-plane addr: A=%v B=%v", errA, errB)
	}
	opA.AddPeer(uuidB, apB)
	opB.AddPeer(uuidA, apA)

	// Each operator learns the other's owned prefix as a peer route.
	if err := opA.SetPeerRoute(benchVNI, uuidB, pfxB); err != nil {
		t.Fatalf("opA SetPeerRoute: %v", err)
	}
	if err := opB.SetPeerRoute(benchVNI, uuidA, pfxA); err != nil {
		t.Fatalf("opB SetPeerRoute: %v", err)
	}

	keys := benchSetup{
		privA: privA, pubA: pubA, privB: privB, pubB: pubB, serverPub: serverPub,
	}
	a = &benchSetup{op: opA, vni: benchVNI, pfxA: pfxA, pfxB: pfxB,
		privA: keys.privA, pubA: keys.pubA, privB: keys.privB, pubB: keys.pubB, serverPub: keys.serverPub}
	b = &benchSetup{op: opB, vni: benchVNI, pfxA: pfxA, pfxB: pfxB,
		privA: keys.privA, pubA: keys.pubA, privB: keys.privB, pubB: keys.pubB, serverPub: keys.serverPub}
	return a, b
}

// startBenchOperator spins up a single operator listening on tp at an
// ephemeral port. Two CIDs are pre-bound to two prefixes inside the VNI
// so client handshakes succeed without a coordinator.
func startBenchOperator(t *testing.T, tp string) *benchSetup {
	t.Helper()

	privA, pubA, err := noise.GenerateKey()
	if err != nil {
		t.Fatalf("genkey A: %v", err)
	}
	privB, pubB, err := noise.GenerateKey()
	if err != nil {
		t.Fatalf("genkey B: %v", err)
	}
	serverPriv, serverPub, err := noise.GenerateKey()
	if err != nil {
		t.Fatalf("genkey server: %v", err)
	}
	pfxA := netip.MustParsePrefix("10.0.200.10/32")
	pfxB := netip.MustParsePrefix("10.0.200.11/32")

	uuid := [16]byte{0xA0}
	cfg := &operator.StaticOperatorConfig{
		UUID:       &uuid,
		StaticPriv: serverPriv,
		ClientListeners: []operator.ListenerSpec{
			{Transport: tp, Addr: "127.0.0.1:0"},
		},
		OpListenAddr: "127.0.0.1:0",
		Network: map[protocol.VNI_Ty]operator.StaticOperatorVNetConfig{
			benchVNI: {
				VNI:            benchVNI,
				CIDR:           benchVNetCIDR,
				AuthorizedKeys: map[noise.PublicKey]struct{}{pubA: {}, pubB: {}},
				PresetKeyMap: map[noise.PublicKey]netip.Prefix{
					pubA: pfxA,
					pubB: pfxB,
				},
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
	return &benchSetup{
		op:    op,
		vni:   benchVNI,
		pfxA:  pfxA,
		pfxB:  pfxB,
		privA: privA, pubA: pubA, privB: privB, pubB: pubB, serverPub: serverPub,
	}
}

// makeIPv4Packet builds a minimal IPv4 packet (no checksum). The
// operator's forwardFrame doesn't validate checksums.
func makeIPv4Packet(src, dst netip.Addr, payload []byte) []byte {
	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45 // version=4, IHL=5
	pkt[2] = byte(totalLen >> 8)
	pkt[3] = byte(totalLen)
	pkt[8] = 64 // TTL
	pkt[9] = 17 // proto = UDP
	s4 := src.As4()
	d4 := dst.As4()
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	copy(pkt[20:], payload)
	return pkt
}

// runTransfer pumps benchRounds * benchRoundSz bytes from connA to
// connB through the operator's L3 forwarder. The operator looks up
// dst IP -> dst CID via routingMap and writes the packet straight to
// connB.
func runTransfer(t *testing.T, label string, connA, connB transport.Conn, srcIP, dstIP netip.Addr) {
	t.Helper()

	pktsPerRound := benchRoundSz / benchPayload
	if benchRoundSz%benchPayload != 0 {
		pktsPerRound++
	}
	totalPkts := int64(pktsPerRound) * int64(benchRounds)
	totalBytes := int64(pktsPerRound) * int64(benchPayload) * int64(benchRounds)
	totalMB := float64(totalBytes) / (1024 * 1024)

	t.Logf("Sending %d rounds x %d MB = %.0f MB total (%d pkts/round, %d bytes/pkt)",
		benchRounds, benchRoundSz/(1024*1024), totalMB, pktsPerRound, benchPayload)

	payload := make([]byte, benchPayload)
	for i := range payload {
		payload[i] = byte(i)
	}
	wire := makeIPv4Packet(srcIP, dstIP, payload)

	profilePath := fmt.Sprintf("../cpu_%s.prof", label)
	f, err := os.Create(profilePath)
	if err != nil {
		t.Fatalf("create profile: %v", err)
	}
	defer f.Close()
	pprof.StartCPUProfile(f)
	defer func() {
		pprof.StopCPUProfile()
		t.Logf("CPU profile saved to %s", profilePath)
	}()

	var rxTotal atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, common.MaxPacketSize)
		for {
			n, err := connB.ReadPacket(buf)
			if err != nil {
				return
			}
			if n > 0 {
				rxTotal.Add(1)
			}
		}
	}()

	start := time.Now()
	for r := 0; r < benchRounds; r++ {
		for p := 0; p < pktsPerRound; p++ {
			if err := connA.WritePacket(wire); err != nil {
				t.Fatalf("round %d pkt %d: send: %v", r, p, err)
			}
		}
		t.Logf("[%s] round %d/%d sent (%d pkts), rx so far %d/%d",
			label, r+1, benchRounds, pktsPerRound, rxTotal.Load(), totalPkts)
	}
	txDone := time.Now()
	txElapsed := txDone.Sub(start)

	// Drain: stop after 5s total or 1s of no progress.
	lastRx := rxTotal.Load()
	lastChange := time.Now()
	for {
		time.Sleep(100 * time.Millisecond)
		cur := rxTotal.Load()
		if cur >= totalPkts {
			break
		}
		if cur != lastRx {
			lastRx = cur
			lastChange = time.Now()
		} else if time.Since(lastChange) > 1*time.Second {
			break
		}
		if time.Since(txDone) > 5*time.Second {
			break
		}
	}
	elapsed := time.Since(start)
	connB.Close()
	wg.Wait()

	rx := rxTotal.Load()
	rxMB := float64(rx) * float64(benchPayload) / (1024 * 1024)
	loss := float64(totalPkts-rx) / float64(totalPkts) * 100

	t.Logf("=== %s ===", label)
	t.Logf("TX:        %.0f MB (%d pkts)", totalMB, totalPkts)
	t.Logf("RX:        %.2f MB (%d pkts), loss %.2f%%", rxMB, rx, loss)
	t.Logf("TX time:   %v", txElapsed.Round(time.Millisecond))
	t.Logf("E2E time:  %v", elapsed.Round(time.Millisecond))
	t.Logf("TX speed:  %.2f MB/s", totalMB/txElapsed.Seconds())
	t.Logf("RX speed:  %.2f MB/s, %.0f pps", rxMB/elapsed.Seconds(), float64(rx)/elapsed.Seconds())
}
