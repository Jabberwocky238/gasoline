package tests

import (
	"testing"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport/tcp"
)

func TestCSC_TCP(t *testing.T) {
	bs := startBenchOperator(t, "tcp")
	defer bs.op.Close()

	cfgA := protocol.NewPresetSessionConfig(bs.cidA, bs.vni)
	connA, _, err := tcp.NewDialer(cfgA, &auth.NoAuthClient{}).Dial(bs.op.ClientAddr())
	if err != nil {
		t.Fatalf("ClientA dial: %v", err)
	}
	defer connA.Close()

	cfgB := protocol.NewPresetSessionConfig(bs.cidB, bs.vni)
	connB, _, err := tcp.NewDialer(cfgB, &auth.NoAuthClient{}).Dial(bs.op.ClientAddr())
	if err != nil {
		t.Fatalf("ClientB dial: %v", err)
	}
	defer connB.Close()

	t.Logf("ClientA=%s  ClientB=%s", bs.pfxA.Addr(), bs.pfxB.Addr())
	runTransfer(t, "CSC-TCP", connA, connB, bs.pfxA.Addr(), bs.pfxB.Addr())
}
