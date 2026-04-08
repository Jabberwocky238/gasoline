package operator

import (
	"fmt"
	"testing"
	"time"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/transport"
)

// blockingListener is a transport.Listener that blocks forever on Accept.
// Used in tests where we only care about the operator endpoint.
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

// TestOperatorDiscovery starts two operators and verifies they can discover each other.
func TestOperatorDiscovery(t *testing.T) {
	uuidA := OperatorUUIDType{0x01}
	uuidB := OperatorUUIDType{0x02}

	opA := New(&Config{
		UUID:               uuidA,
		ClientListener:     newBlockingListener(),
		OperatorListenAddr: "127.0.0.1:0", // port 0 = auto assign
	})
	opB := New(&Config{
		UUID:               uuidB,
		ClientListener:     newBlockingListener(),
		OperatorListenAddr: "127.0.0.1:0",
	})

	if err := opA.Start(); err != nil {
		t.Fatalf("opA start: %v", err)
	}
	defer opA.Close()

	if err := opB.Start(); err != nil {
		t.Fatalf("opB start: %v", err)
	}
	defer opB.Close()

	// A dials B's operator endpoint
	addrB := opB.opListener.Addr().String()
	if err := opA.DialOperator(addrB); err != nil {
		t.Fatalf("opA dial opB: %v", err)
	}

	// Wait for registration to propagate
	time.Sleep(100 * time.Millisecond)

	// A should know about B
	if opA.ConnectedOperators() != 1 {
		t.Fatalf("opA expected 1 operator peer, got %d", opA.ConnectedOperators())
	}
	if _, ok := opA.Registry.GetOperator(uuidB); !ok {
		t.Fatal("opA registry does not contain opB")
	}

	// B should know about A
	if opB.ConnectedOperators() != 1 {
		t.Fatalf("opB expected 1 operator peer, got %d", opB.ConnectedOperators())
	}
	if _, ok := opB.Registry.GetOperator(uuidA); !ok {
		t.Fatal("opB registry does not contain opA")
	}

	t.Logf("Discovery OK: A(%x) <-> B(%x)", uuidA[:4], uuidB[:4])
}

// TestOperatorAutoDiscover tests that C only connects to A (seed),
// then auto-discovers B through A's operator list.
// Topology: A <-> B (manual), C -> A (seed) -> discovers B -> C <-> B (auto)
func TestOperatorAutoDiscover(t *testing.T) {
	uuidA := OperatorUUIDType{0x0A}
	uuidB := OperatorUUIDType{0x0B}
	uuidC := OperatorUUIDType{0x0C}

	// Start A and B, connect them manually
	opA := New(&Config{
		UUID:               uuidA,
		ClientListener:     newBlockingListener(),
		OperatorListenAddr: "127.0.0.1:0",
	})
	opB := New(&Config{
		UUID:               uuidB,
		ClientListener:     newBlockingListener(),
		OperatorListenAddr: "127.0.0.1:0",
	})

	if err := opA.Start(); err != nil {
		t.Fatalf("opA start: %v", err)
	}
	defer opA.Close()
	// Set external addr to actual bound address (port 0 was auto-assigned)
	opA.cfg.OperatorExternalAddr = opA.opListener.Addr().String()

	if err := opB.Start(); err != nil {
		t.Fatalf("opB start: %v", err)
	}
	defer opB.Close()
	opB.cfg.OperatorExternalAddr = opB.opListener.Addr().String()

	// A dials B
	if err := opA.DialOperator(opB.cfg.OperatorExternalAddr); err != nil {
		t.Fatalf("A dial B: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	// Now start C with A as seed — C should auto-discover B
	opC := New(&Config{
		UUID:                uuidC,
		ClientListener:      newBlockingListener(),
		OperatorListenAddr:  "127.0.0.1:0",
		OperatorExternalAddr: "127.0.0.1:0", // placeholder, set after Start
		DiscoverAddrs:       []string{opA.cfg.OperatorExternalAddr},
	})
	if err := opC.Start(); err != nil {
		t.Fatalf("opC start: %v", err)
	}
	defer opC.Close()
	opC.cfg.OperatorExternalAddr = opC.opListener.Addr().String()

	// Poll until C knows both A and B
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

// TestOperatorPingPong tests that Ping/Pong works between two operators
// and that PingCost is updated in the Registry.
func TestOperatorPingPong(t *testing.T) {
	uuidA := OperatorUUIDType{0xAA}
	uuidB := OperatorUUIDType{0xBB}

	opA := New(&Config{
		UUID:               uuidA,
		ClientListener:     newBlockingListener(),
		OperatorListenAddr: "127.0.0.1:0",
	})
	opB := New(&Config{
		UUID:               uuidB,
		ClientListener:     newBlockingListener(),
		OperatorListenAddr: "127.0.0.1:0",
	})

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

	// A pings B
	if err := opA.PingOperator(uuidB); err != nil {
		t.Fatalf("ping: %v", err)
	}

	// Poll until LastPing is set (PingCost can be 0 on localhost)
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
