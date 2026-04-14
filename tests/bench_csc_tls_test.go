package tests

import (
	"testing"

	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport/quic"
	tlstransport "github.com/jabberwocky238/gasoline/transport/tls"
)

func TestCSC_TLS(t *testing.T) {
	op, vni := setupSingleOperator(t, "tls")
	defer op.Close()

	tlsConf := quic.InsecureClientTLS()

	connA, resultA, err := tlstransport.NewDialer([16]byte{0x01}, vni, &auth.NoAuthClient{}, tlsConf).Dial(op.ClientAddr())
	if err != nil {
		t.Fatalf("ClientA dial: %v", err)
	}
	defer connA.Close()

	connB, resultB, err := tlstransport.NewDialer([16]byte{0x02}, vni, &auth.NoAuthClient{}, tlsConf).Dial(op.ClientAddr())
	if err != nil {
		t.Fatalf("ClientB dial: %v", err)
	}
	defer connB.Close()

	clientAIP := resultA.Config.IPPrefix.Addr()
	clientBIP := resultB.Config.IPPrefix.Addr()
	t.Logf("ClientA=%s  ClientB=%s", clientAIP, clientBIP)

	runTransfer(t, "CSC-TLS", connA, connB, clientAIP, clientBIP)
}
