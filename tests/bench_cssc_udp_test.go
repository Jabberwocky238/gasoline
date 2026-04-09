package tests

import (
	"testing"

	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport/udp"
)

func TestCSSC_UDP(t *testing.T) {
	opA, opB, vnetID := setupOperators(t, "udp")
	defer opA.Close()
	defer opB.Close()

	connA, resultA, err := udp.NewDialer([16]byte{0x01}, vnetID, &auth.NoAuthClient{}).Dial(opA.ClientAddr())
	if err != nil {
		t.Fatalf("ClientA dial: %v", err)
	}
	defer connA.Close()

	connB, resultB, err := udp.NewDialer([16]byte{0x02}, vnetID, &auth.NoAuthClient{}).Dial(opB.ClientAddr())
	if err != nil {
		t.Fatalf("ClientB dial: %v", err)
	}
	defer connB.Close()

	clientAIP := resultA.Config.IPPrefix.Addr()
	clientBIP := resultB.Config.IPPrefix.Addr()
	t.Logf("ClientA=%s  ClientB=%s", clientAIP, clientBIP)

	waitFor(t, 2e9, func() bool {
		_, found := opA.Ctrl.LookupRemoteSession(vnetID, clientBIP)
		return found
	})

	runTransfer(t, "UDP", connA, connB, clientAIP, clientBIP)
}
