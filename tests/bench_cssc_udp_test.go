package tests

import (
	"testing"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/transport/udp"
)

func TestCSSC_UDP(t *testing.T) {
	a, b := startBenchOperators(t, "udp")
	defer a.op.Close()
	defer b.op.Close()

	cfgA := protocol.NewPresetSessionConfig(a.vni)
	connA, _ := dialAndAssign(t, udp.NewDialer(cfgA, a.idA()), a.op.ClientAddr(), a.idA(), a.vni)
	defer connA.Close()

	cfgB := protocol.NewPresetSessionConfig(b.vni)
	connB, _ := dialAndAssign(t, udp.NewDialer(cfgB, b.idB()), b.op.ClientAddr(), b.idB(), b.vni)
	defer connB.Close()

	t.Logf("ClientA=%s  ClientB=%s", a.pfxA.Addr(), b.pfxB.Addr())
	runTransfer(t, "CSSC-UDP", connA, connB, a.pfxA.Addr(), b.pfxB.Addr())
}
