package operator

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jabberwocky238/gasoline/common"
)

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
