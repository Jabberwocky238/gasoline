package tls

import (
	"crypto/tls"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport"
)

type Dialer struct {
	clientID common.ClientID
	vni      common.VNI
	auth     auth.ClientAuthenticator
	tlsConf  *tls.Config
}

func NewDialer(clientID common.ClientID, vni common.VNI, auth auth.ClientAuthenticator, tlsConf *tls.Config) *Dialer {
	return &Dialer{clientID: clientID, vni: vni, auth: auth, tlsConf: tlsConf}
}

func (d *Dialer) Dial(endpoint string) (transport.Conn, *protocol.HandshakeResult, error) {
	raw, err := tls.Dial("tcp", endpoint, d.tlsConf)
	if err != nil {
		return nil, nil, err
	}
	result, err := protocol.ClientHandshake(raw, d.clientID, d.vni, d.auth)
	if err != nil {
		raw.Close()
		return nil, nil, err
	}
	return newConn(raw, result.Keypair), result, nil
}
