package tests

import (
	"testing"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/transport/quic"
)

func TestCSC_QUIC(t *testing.T) {
	bs := startBenchOperator(t, "quic")
	defer bs.op.Close()

	tlsConf := quic.InsecureClientTLS()

	cfgA := protocol.NewPresetSessionConfig(bs.cidA, bs.vni)
	connA, _, err := quic.NewDialer(cfgA, bs.idA(), tlsConf).Dial(bs.op.ClientAddr())
	if err != nil {
		t.Fatalf("ClientA dial: %v", err)
	}
	defer connA.Close()

	cfgB := protocol.NewPresetSessionConfig(bs.cidB, bs.vni)
	connB, _, err := quic.NewDialer(cfgB, bs.idB(), tlsConf).Dial(bs.op.ClientAddr())
	if err != nil {
		t.Fatalf("ClientB dial: %v", err)
	}
	defer connB.Close()

	t.Logf("ClientA=%s  ClientB=%s", bs.pfxA.Addr(), bs.pfxB.Addr())
	runTransfer(t, "CSC-QUIC", connA, connB, bs.pfxA.Addr(), bs.pfxB.Addr())
}
