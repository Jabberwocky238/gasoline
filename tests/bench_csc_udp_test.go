package tests

import (
	"testing"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport/udp"
)

func TestCSC_UDP(t *testing.T) {
	bs := startBenchOperator(t, "udp")
	defer bs.op.Close()

	cfgA := protocol.NewPresetSessionConfig(bs.cidA, bs.vni)
	connA, _, err := udp.NewDialer(cfgA, &auth.NoAuthClient{}).Dial(bs.op.ClientAddr())
	if err != nil {
		t.Fatalf("ClientA dial: %v", err)
	}
	defer connA.Close()

	cfgB := protocol.NewPresetSessionConfig(bs.cidB, bs.vni)
	connB, _, err := udp.NewDialer(cfgB, &auth.NoAuthClient{}).Dial(bs.op.ClientAddr())
	if err != nil {
		t.Fatalf("ClientB dial: %v", err)
	}
	defer connB.Close()

	t.Logf("ClientA=%s  ClientB=%s", bs.pfxA.Addr(), bs.pfxB.Addr())
	runTransfer(t, "CSC-UDP", connA, connB, bs.pfxA.Addr(), bs.pfxB.Addr())
}
