package tests

import (
	"testing"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport/quic"
	tlstransport "github.com/jabberwocky238/gasoline/transport/tls"
)

func TestCSSC_TLS(t *testing.T) {
	a, b := startBenchOperators(t, "tls")
	defer a.op.Close()
	defer b.op.Close()

	tlsConf := quic.InsecureClientTLS()

	cfgA := protocol.NewPresetSessionConfig(a.cidA, a.vni)
	connA, _, err := tlstransport.NewDialer(cfgA, &auth.NoAuthClient{}, tlsConf).Dial(a.op.ClientAddr())
	if err != nil {
		t.Fatalf("ClientA dial: %v", err)
	}
	defer connA.Close()

	cfgB := protocol.NewPresetSessionConfig(b.cidB, b.vni)
	connB, _, err := tlstransport.NewDialer(cfgB, &auth.NoAuthClient{}, tlsConf).Dial(b.op.ClientAddr())
	if err != nil {
		t.Fatalf("ClientB dial: %v", err)
	}
	defer connB.Close()

	t.Logf("ClientA=%s  ClientB=%s", a.pfxA.Addr(), b.pfxB.Addr())
	runTransfer(t, "CSSC-TLS", connA, connB, a.pfxA.Addr(), b.pfxB.Addr())
}
