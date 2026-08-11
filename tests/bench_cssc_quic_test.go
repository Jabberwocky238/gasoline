package tests

import (
	"testing"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/transport/quic"
)

func TestCSSC_QUIC(t *testing.T) {
	a, b := startBenchOperators(t, "quic")
	defer a.op.Close()
	defer b.op.Close()

	tlsConf := quic.InsecureClientTLS()

	cfgA := protocol.NewPresetSessionConfig(a.cidA, a.vni)
	connA, _ := dialAndAssign(t, quic.NewDialer(cfgA, a.idA(), tlsConf), a.op.ClientAddr(), a.idA(), a.vni)
	defer connA.Close()

	cfgB := protocol.NewPresetSessionConfig(b.cidB, b.vni)
	connB, _ := dialAndAssign(t, quic.NewDialer(cfgB, b.idB(), tlsConf), b.op.ClientAddr(), b.idB(), b.vni)
	defer connB.Close()

	t.Logf("ClientA=%s  ClientB=%s", a.pfxA.Addr(), b.pfxB.Addr())
	runTransfer(t, "CSSC-QUIC", connA, connB, a.pfxA.Addr(), b.pfxB.Addr())
}
