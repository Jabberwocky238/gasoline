package tests

import (
	"testing"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport/tcp"
)

func TestCSSC_TCP(t *testing.T) {
	opA, opB, vni := setupOperators(t, "tcp")
	defer opA.Close()
	defer opB.Close()

	connA, resultA, err := tcp.NewDialer(common.ClientID{0x02, 0, 0, 0, 0, 0x01}, vni, &auth.NoAuthClient{}).Dial(opA.ClientAddr())
	if err != nil {
		t.Fatalf("ClientA dial: %v", err)
	}
	defer connA.Close()

	connB, resultB, err := tcp.NewDialer(common.ClientID{0x02, 0, 0, 0, 0, 0x02}, vni, &auth.NoAuthClient{}).Dial(opB.ClientAddr())
	if err != nil {
		t.Fatalf("ClientB dial: %v", err)
	}
	defer connB.Close()

	clientAIP := resultA.Config.IPPrefix.Addr()
	clientBIP := resultB.Config.IPPrefix.Addr()
	t.Logf("ClientA=%s  ClientB=%s", clientAIP, clientBIP)

	waitFor(t, 2e9, func() bool {
		_, _, _, found := opA.Ctrl.LookupRemoteSessionByIP(vni, clientBIP)
		return found
	})

	runTransfer(t, "CSSC-TCP", connA, connB, clientAIP, clientBIP)
}
