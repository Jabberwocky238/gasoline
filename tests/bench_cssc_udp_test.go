package tests

import (
	"testing"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport/udp"
)

func TestCSSC_UDP(t *testing.T) {
	a, b := startBenchOperators(t, "udp")
	defer a.op.Close()
	defer b.op.Close()

	cfgA := protocol.NewPreassignedSessionConfig(a.cidA, a.vni)
	connA, _, err := udp.NewDialer(cfgA, &auth.NoAuthClient{}).Dial(a.op.ClientAddr())
	if err != nil {
		t.Fatalf("ClientA dial: %v", err)
	}
	defer connA.Close()

	cfgB := protocol.NewPreassignedSessionConfig(b.cidB, b.vni)
	connB, _, err := udp.NewDialer(cfgB, &auth.NoAuthClient{}).Dial(b.op.ClientAddr())
	if err != nil {
		t.Fatalf("ClientB dial: %v", err)
	}
	defer connB.Close()

	t.Logf("ClientA=%s  ClientB=%s", a.pfxA.Addr(), b.pfxB.Addr())
	runTransfer(t, "CSSC-UDP", connA, connB, a.pfxA.Addr(), b.pfxB.Addr())
}
