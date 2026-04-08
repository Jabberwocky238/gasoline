package operator

import (
	"fmt"
	"testing"
	"time"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/transport"
)

// blockingListener is a transport.Listener that blocks forever on Accept.
type blockingListener struct {
	done chan struct{}
}

func newBlockingListener() *blockingListener {
	return &blockingListener{done: make(chan struct{})}
}

func (l *blockingListener) Accept() (transport.Conn, *protocol.HandshakeResult, error) {
	<-l.done
	return nil, nil, fmt.Errorf("listener closed")
}

func (l *blockingListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

func (l *blockingListener) Addr() string { return "test://noop" }

// newTestOperator creates a minimal operator for testing with a given UUID.
// It bypasses New() to avoid needing real network/auth config.
func newTestOperator(uuid OperatorUUIDType, cfg *common.OperatorConfig) *Operator {
	id := [16]byte(uuid)
	cfg.UUID = &id
	op, err := New(cfg)
	if err != nil {
		panic(fmt.Sprintf("newTestOperator: %v", err))
	}
	return op
}

func TestOperatorDiscovery(t *testing.T) {
	uuidA := OperatorUUIDType{0x01}
	uuidB := OperatorUUIDType{0x02}

	opA := newTestOperator(uuidA, &common.OperatorConfig{OpListenAddr: "127.0.0.1:0"})
	opB := newTestOperator(uuidB, &common.OperatorConfig{OpListenAddr: "127.0.0.1:0"})

	if err := opA.Start(); err != nil {
		t.Fatalf("opA start: %v", err)
	}
	defer opA.Close()

	if err := opB.Start(); err != nil {
		t.Fatalf("opB start: %v", err)
	}
	defer opB.Close()

	addrB := opB.opListener.Addr().String()
	if err := opA.DialOperator(addrB); err != nil {
		t.Fatalf("opA dial opB: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	if opA.ConnectedOperators() != 1 {
		t.Fatalf("opA expected 1 operator peer, got %d", opA.ConnectedOperators())
	}
	if _, ok := opA.Registry.GetOperator(uuidB); !ok {
		t.Fatal("opA registry does not contain opB")
	}

	if opB.ConnectedOperators() != 1 {
		t.Fatalf("opB expected 1 operator peer, got %d", opB.ConnectedOperators())
	}
	if _, ok := opB.Registry.GetOperator(uuidA); !ok {
		t.Fatal("opB registry does not contain opA")
	}

	t.Logf("Discovery OK: A(%x) <-> B(%x)", uuidA[:4], uuidB[:4])
}

func TestOperatorAutoDiscover(t *testing.T) {
	uuidA := OperatorUUIDType{0x0A}
	uuidB := OperatorUUIDType{0x0B}
	uuidC := OperatorUUIDType{0x0C}

	opA := newTestOperator(uuidA, &common.OperatorConfig{OpListenAddr: "127.0.0.1:0"})
	opB := newTestOperator(uuidB, &common.OperatorConfig{OpListenAddr: "127.0.0.1:0"})

	if err := opA.Start(); err != nil {
		t.Fatalf("opA start: %v", err)
	}
	defer opA.Close()
	opA.cfg.OpExternalAddr = opA.opListener.Addr().String()

	if err := opB.Start(); err != nil {
		t.Fatalf("opB start: %v", err)
	}
	defer opB.Close()
	opB.cfg.OpExternalAddr = opB.opListener.Addr().String()

	if err := opA.DialOperator(opB.cfg.OpExternalAddr); err != nil {
		t.Fatalf("A dial B: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	opC := newTestOperator(uuidC, &Config{
		OpListenAddr:   "127.0.0.1:0",
		OpExternalAddr: "127.0.0.1:0",
		DiscoverAddrs:  []string{opA.cfg.OpExternalAddr},
	})
	if err := opC.Start(); err != nil {
		t.Fatalf("opC start: %v", err)
	}
	defer opC.Close()
	opC.cfg.OpExternalAddr = opC.opListener.Addr().String()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if opC.ConnectedOperators() >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if opC.ConnectedOperators() < 2 {
		t.Fatalf("opC expected 2 peers, got %d", opC.ConnectedOperators())
	}
	if _, ok := opC.Registry.GetOperator(uuidA); !ok {
		t.Fatal("opC registry missing A")
	}
	if _, ok := opC.Registry.GetOperator(uuidB); !ok {
		t.Fatal("opC registry missing B")
	}

	t.Logf("Auto-discover OK: C found A and B via seed")
}

func TestOperatorPingPong(t *testing.T) {
	uuidA := OperatorUUIDType{0xAA}
	uuidB := OperatorUUIDType{0xBB}

	opA := newTestOperator(uuidA, &common.OperatorConfig{OpListenAddr: "127.0.0.1:0"})
	opB := newTestOperator(uuidB, &common.OperatorConfig{OpListenAddr: "127.0.0.1:0"})

	if err := opA.Start(); err != nil {
		t.Fatalf("opA start: %v", err)
	}
	defer opA.Close()
	if err := opB.Start(); err != nil {
		t.Fatalf("opB start: %v", err)
	}
	defer opB.Close()

	addrB := opB.opListener.Addr().String()
	if err := opA.DialOperator(addrB); err != nil {
		t.Fatalf("dial: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	if err := opA.PingOperator(uuidB); err != nil {
		t.Fatalf("ping: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		entry, ok := opA.Registry.GetOperator(uuidB)
		if ok && !entry.LastPing.IsZero() {
			t.Logf("Ping-Pong OK: RTT=%v, LastPing=%v", entry.PingCost, entry.LastPing)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("LastPing was not set within timeout")
}
