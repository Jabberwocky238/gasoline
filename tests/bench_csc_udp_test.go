package tests

import (
	"testing"

	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport/udp"
)

func TestCSC_UDP(t *testing.T) {
	op, vni := setupSingleOperator(t, "udp")
	defer op.Close()

	connA, resultA, err := udp.NewDialer([16]byte{0x01}, vni, &auth.NoAuthClient{}).Dial(op.ClientAddr())
	if err != nil {
		t.Fatalf("ClientA dial: %v", err)
	}
	defer connA.Close()

	connB, resultB, err := udp.NewDialer([16]byte{0x02}, vni, &auth.NoAuthClient{}).Dial(op.ClientAddr())
	if err != nil {
		t.Fatalf("ClientB dial: %v", err)
	}
	defer connB.Close()

	clientAIP := resultA.Config.IPPrefix.Addr()
	clientBIP := resultB.Config.IPPrefix.Addr()
	t.Logf("ClientA=%s  ClientB=%s", clientAIP, clientBIP)

	runTransfer(t, "CSC-UDP", connA, connB, clientAIP, clientBIP)
}
