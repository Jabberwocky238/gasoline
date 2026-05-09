package tests

import (
	"testing"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport/quic"
)

func TestCSSC_QUIC(t *testing.T) {
	opA, opB, vni := setupOperators(t, "quic")
	defer opA.Close()
	defer opB.Close()

	tlsConf := quic.InsecureClientTLS()

	connA, resultA, err := quic.NewDialer(common.VMAC{0x02, 0, 0, 0, 0, 0x01}, vni, &auth.NoAuthClient{}, tlsConf).Dial(opA.ClientAddr())
	if err != nil {
		t.Fatalf("ClientA dial: %v", err)
	}
	defer connA.Close()

	connB, resultB, err := quic.NewDialer(common.VMAC{0x02, 0, 0, 0, 0, 0x02}, vni, &auth.NoAuthClient{}, tlsConf).Dial(opB.ClientAddr())
	if err != nil {
		t.Fatalf("ClientB dial: %v", err)
	}
	defer connB.Close()

	clientAIP := resultA.Config.IPPrefix.Addr()
	clientBIP := resultB.Config.IPPrefix.Addr()
	t.Logf("ClientA=%s  ClientB=%s", clientAIP, clientBIP)

	waitFor(t, 2e9, func() bool {
		_, _, found := opA.LookupRemoteByVMAC(vni, resultB.VMAC)
		return found
	})

	runTransfer(t, "CSSC-QUIC", connA, connB, clientAIP, clientBIP, resultA.VMAC, resultB.VMAC)
}
