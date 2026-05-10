package tests

import (
	"testing"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport/tcp"
)

func TestCSSC_TCP(t *testing.T) {
	a, b := startBenchOperators(t, "tcp")
	defer a.op.Close()
	defer b.op.Close()

	cfgA := protocol.NewPresetSessionConfig(a.cidA, a.vni)
	connA, _, err := tcp.NewDialer(cfgA, &auth.NoAuthClient{}).Dial(a.op.ClientAddr())
	if err != nil {
		t.Fatalf("ClientA dial: %v", err)
	}
	defer connA.Close()

	cfgB := protocol.NewPresetSessionConfig(b.cidB, b.vni)
	connB, _, err := tcp.NewDialer(cfgB, &auth.NoAuthClient{}).Dial(b.op.ClientAddr())
	if err != nil {
		t.Fatalf("ClientB dial: %v", err)
	}
	defer connB.Close()

	t.Logf("ClientA=%s  ClientB=%s", a.pfxA.Addr(), b.pfxB.Addr())
	runTransfer(t, "CSSC-TCP", connA, connB, a.pfxA.Addr(), b.pfxB.Addr())
}
