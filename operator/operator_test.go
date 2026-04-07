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

// TestOperatorTriangle tests three operators forming a mesh.
func TestOperatorTriangle(t *testing.T) {
	uuidA := OperatorUUIDType{0x0A}
	uuidB := OperatorUUIDType{0x0B}
	uuidC := OperatorUUIDType{0x0C}

	ops := make([]*Operator, 3)
	uuids := []OperatorUUIDType{uuidA, uuidB, uuidC}

	for i, uuid := range uuids {
		ops[i] = New(&Config{
			UUID:               uuid,
			ClientListener:     newBlockingListener(),
			OperatorListenAddr: "127.0.0.1:0",
		})
		if err := ops[i].Start(); err != nil {
			t.Fatalf("op[%d] start: %v", i, err)
		}
		defer ops[i].Close()
	}

	// A->B, A->C, B->C
	pairs := [][2]int{{0, 1}, {0, 2}, {1, 2}}
	for _, p := range pairs {
		addr := ops[p[1]].opListener.Addr().String()
		if err := ops[p[0]].DialOperator(addr); err != nil {
			t.Fatalf("op[%d] dial op[%d]: %v", p[0], p[1], err)
		}
	}

	time.Sleep(100 * time.Millisecond)

	// A: knows B and C
	if opA := ops[0]; opA.ConnectedOperators() != 2 {
		t.Fatalf("opA expected 2 peers, got %d", opA.ConnectedOperators())
	}
	// B: knows A and C
	if opB := ops[1]; opB.ConnectedOperators() != 2 {
		t.Fatalf("opB expected 2 peers, got %d", opB.ConnectedOperators())
	}
	// C: knows A and B
	if opC := ops[2]; opC.ConnectedOperators() != 2 {
		t.Fatalf("opC expected 2 peers, got %d", opC.ConnectedOperators())
	}

	t.Log("Triangle mesh OK: A <-> B <-> C <-> A")
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

	// Poll until PingCost is updated or timeout
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		entry, ok := opA.Registry.GetOperator(uuidB)
		if ok && entry.PingCost > 0 {
			t.Logf("Ping-Pong OK: RTT=%v, LastPing=%v", entry.PingCost, entry.LastPing)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("PingCost was not updated within timeout")
}
