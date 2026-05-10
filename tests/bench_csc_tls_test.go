package tests

import (
	"testing"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport/quic"
	tlstransport "github.com/jabberwocky238/gasoline/transport/tls"
)

func TestCSC_TLS(t *testing.T) {
	bs := startBenchOperator(t, "tls")
	defer bs.op.Close()

	tlsConf := quic.InsecureClientTLS()

	cfgA := protocol.NewPresetSessionConfig(bs.cidA, bs.vni)
	connA, _, err := tlstransport.NewDialer(cfgA, &auth.NoAuthClient{}, tlsConf).Dial(bs.op.ClientAddr())
	if err != nil {
		t.Fatalf("ClientA dial: %v", err)
	}
	defer connA.Close()

	cfgB := protocol.NewPresetSessionConfig(bs.cidB, bs.vni)
	connB, _, err := tlstransport.NewDialer(cfgB, &auth.NoAuthClient{}, tlsConf).Dial(bs.op.ClientAddr())
	if err != nil {
		t.Fatalf("ClientB dial: %v", err)
	}
	defer connB.Close()

	t.Logf("ClientA=%s  ClientB=%s", bs.pfxA.Addr(), bs.pfxB.Addr())
	runTransfer(t, "CSC-TLS", connA, connB, bs.pfxA.Addr(), bs.pfxB.Addr())
}
