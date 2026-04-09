package tests

import (
	"testing"

	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport/quic"
)

func TestCSSC_QUIC(t *testing.T) {
	opA, opB, vnetID := setupOperators(t, "quic")
	defer opA.Close()
	defer opB.Close()

	tlsConf := quic.InsecureClientTLS()

	connA, resultA, err := quic.NewDialer([16]byte{0x01}, vnetID, &auth.NoAuthClient{}, tlsConf).Dial(opA.ClientAddr())
	if err != nil {
		t.Fatalf("ClientA dial: %v", err)
	}
	defer connA.Close()

	connB, resultB, err := quic.NewDialer([16]byte{0x02}, vnetID, &auth.NoAuthClient{}, tlsConf).Dial(opB.ClientAddr())
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

	runTransfer(t, "QUIC", connA, connB, clientAIP, clientBIP)
}
