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

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/common/config"
	"github.com/jabberwocky238/gasoline/operator"
	"github.com/jabberwocky238/gasoline/transport"
)

const (
	benchVNetNum  = 200
	benchVNetCIDR = "10.0.200.0/24"
	benchPayload  = 1380
	benchRoundSz  = 10 * 1024 * 1024
	benchRounds   = 10
)

func startBenchOperator(t *testing.T, uuid [16]byte, tp string) *operator.Operator {
	t.Helper()
	vnetStr := fmt.Sprintf("%d:%s", benchVNetNum, benchVNetCIDR)
	cfg := &config.OperatorConfig{
		UUID:            &uuid,
		ClientListeners: []config.ListenerSpec{{Transport: tp, Addr: "127.0.0.1:0"}},
		OpListenAddr:    "127.0.0.1:0",
		AuthStr:         "noauth",
		Network:         vnetStr,
		StatsAddr:       "",
		LogLevel:        "error",
	}
	op, err := operator.New(cfg)
	if err != nil {
		t.Fatalf("new operator %x: %v", uuid, err)
	}
	if err := op.Start(); err != nil {
		t.Fatalf("start operator %x: %v", uuid, err)
	}
	op.Ctrl.SetExternalAddr(op.GRPCAddr())
	return op
}

func setupSingleOperator(t *testing.T, tp string) (*operator.Operator, common.VNI) {
	t.Helper()
	vni := common.VNI(benchVNetNum)
	op := startBenchOperator(t, [16]byte{0xA0}, tp)
	return op, vni
}

func setupOperators(t *testing.T, tp string) (*operator.Operator, *operator.Operator, common.VNI) {
	t.Helper()
	vni := common.VNI(benchVNetNum)
	opA := startBenchOperator(t, [16]byte{0xA0}, tp)
	opB := startBenchOperator(t, [16]byte{0xB0}, tp)

	if err := opA.Ctrl.DialOperator(opB.GRPCAddr()); err != nil {
		t.Fatalf("A dial B: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool {
		return opA.ConnectedOperators() >= 1 && opB.ConnectedOperators() >= 1
	})
	return opA, opB, vni
}

func makeIPv4Packet(src, dst netip.Addr, payload []byte) []byte {
	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	pkt[2] = byte(totalLen >> 8)
	pkt[3] = byte(totalLen)
	pkt[8] = 64
	pkt[9] = 17
	s4 := src.As4()
	d4 := dst.As4()
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	copy(pkt[20:], payload)
	return pkt
}

func runTransfer(t *testing.T, label string, connA, connB transport.Conn, srcIP, dstIP netip.Addr, srcMAC, dstMAC common.VMAC) {
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
	ipPkt := makeIPv4Packet(srcIP, dstIP, payload)

	// Operator data plane is L2 — wrap the IP packet in an Ethernet header
	// (dstMAC = clientB's VMAC, srcMAC = clientA's VMAC) before sending.
	// WrapEth now returns a pooled DataFrame; reused across the whole loop.
	df := common.WrapEth(dstMAC, srcMAC, common.EtherTypeIPv4, ipPkt)
	defer common.PutFrame(df)
	wire := df.Bytes()

	// CPU profile — output to project root
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
		t.Logf("  View: go tool pprof -http=:8080 %s", profilePath)
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
				return // connB closed, exit
			}
			if n > 0 {
				rxTotal.Add(1)
			}
		}
	}()

	start := time.Now()
	for r := 0; r < benchRounds; r++ {
		roundStart := time.Now()
		for p := 0; p < pktsPerRound; p++ {
			if err := connA.WritePacket(wire); err != nil {
				t.Fatalf("round %d pkt %d: send error: %v", r, p, err)
			}
		}
		t.Logf("[%s] round %d/%d sent (%d pkts), tx %.0fms, rx so far %d/%d",
			label, r+1, benchRounds, pktsPerRound,
			float64(time.Since(roundStart).Milliseconds()),
			rxTotal.Load(), totalPkts)
	}
	txDone := time.Now()
	txElapsed := txDone.Sub(start)
	t.Logf("[%s] all rounds sent, TX done in %v, draining...", label, txElapsed.Round(time.Millisecond))

	// Drain: wait up to 5s for remaining packets, stop early if no progress for 1s
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
	connB.Close() // unblock ReadPacket
	wg.Wait()

	rx := rxTotal.Load()
	rxMB := float64(rx) * float64(benchPayload) / (1024 * 1024)
	loss := float64(totalPkts-rx) / float64(totalPkts) * 100

	t.Logf("=== %s C-S-S-C Transfer ===", label)
	t.Logf("Total TX:   %.0f MB (%d packets)", totalMB, totalPkts)
	t.Logf("Total RX:   %.2f MB (%d packets)", rxMB, rx)
	t.Logf("Loss:       %.2f%% (%d packets)", loss, totalPkts-rx)
	t.Logf("TX time:    %v", txElapsed.Round(time.Millisecond))
	t.Logf("E2E time:   %v", elapsed.Round(time.Millisecond))
	t.Logf("TX speed:   %.2f MB/s", totalMB/txElapsed.Seconds())
	t.Logf("RX speed:   %.2f MB/s", rxMB/elapsed.Seconds())
	t.Logf("Avg PPS:    %.0f", float64(rx)/elapsed.Seconds())
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("waitFor: timed out")
}
