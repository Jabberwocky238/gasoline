package tests

import (
	"testing"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/transport/udp"
)

func TestCSC_UDP(t *testing.T) {
	bs := startBenchOperator(t, "udp")
	defer bs.op.Close()

	cfgA := protocol.NewPresetSessionConfig(bs.vni)
	connA, _ := dialAndAssign(t, udp.NewDialer(cfgA, bs.idA()), bs.op.ClientAddr(), bs.idA(), bs.vni)
	defer connA.Close()

	cfgB := protocol.NewPresetSessionConfig(bs.vni)
	connB, _ := dialAndAssign(t, udp.NewDialer(cfgB, bs.idB()), bs.op.ClientAddr(), bs.idB(), bs.vni)
	defer connB.Close()

	t.Logf("ClientA=%s  ClientB=%s", bs.pfxA.Addr(), bs.pfxB.Addr())
	runTransfer(t, "CSC-UDP", connA, connB, bs.pfxA.Addr(), bs.pfxB.Addr())
}
