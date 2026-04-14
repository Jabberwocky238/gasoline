package quic

import (
	"context"
	"crypto/tls"

	"github.com/quic-go/quic-go"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport"
)

type Dialer struct {
	vmac common.VMAC
	vni      common.VNI
	auth     auth.ClientAuthenticator
	tlsConf  *tls.Config
}

func NewDialer(vmac common.VMAC, vni common.VNI, auth auth.ClientAuthenticator, tlsConf *tls.Config) *Dialer {
	return &Dialer{vmac:     vmac, vni: vni, auth: auth, tlsConf: tlsConf}
}

func (d *Dialer) Dial(endpoint string) (transport.Conn, *protocol.HandshakeResult, error) {
	conn, err := quic.DialAddr(context.Background(), endpoint, d.tlsConf, nil)
	if err != nil {
		return nil, nil, err
	}
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		conn.CloseWithError(0, "stream open failed")
		return nil, nil, err
	}

	result, err := protocol.ClientHandshake(stream, d.vmac, d.vni, d.auth)
	if err != nil {
		conn.CloseWithError(0, "handshake failed")
		return nil, nil, err
	}

	return newConn(stream, result.Keypair, conn.RemoteAddr().String()), result, nil
}
