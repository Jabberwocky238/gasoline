package tests

import (
	"testing"

	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport/tcp"
)

func TestCSC_TCP(t *testing.T) {
	op, vnetID := setupSingleOperator(t, "tcp")
	defer op.Close()

	connA, resultA, err := tcp.NewDialer([16]byte{0x01}, vnetID, &auth.NoAuthClient{}).Dial(op.ClientAddr())
	if err != nil {
		t.Fatalf("ClientA dial: %v", err)
	}
	defer connA.Close()

	connB, resultB, err := tcp.NewDialer([16]byte{0x02}, vnetID, &auth.NoAuthClient{}).Dial(op.ClientAddr())
	if err != nil {
		t.Fatalf("ClientB dial: %v", err)
	}
	defer connB.Close()

	clientAIP := resultA.Config.IPPrefix.Addr()
	clientBIP := resultB.Config.IPPrefix.Addr()
	t.Logf("ClientA=%s  ClientB=%s", clientAIP, clientBIP)

	runTransfer(t, "CSC-TCP", connA, connB, clientAIP, clientBIP)
}
