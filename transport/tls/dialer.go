package tls

import (
	"crypto/tls"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport"
)

type Dialer struct {
	clientID [16]byte
	vnetID   [16]byte
	auth     auth.ClientAuthenticator
	tlsConf  *tls.Config
}

func NewDialer(clientID [16]byte, vnetID [16]byte, auth auth.ClientAuthenticator, tlsConf *tls.Config) *Dialer {
	return &Dialer{clientID: clientID, vnetID: vnetID, auth: auth, tlsConf: tlsConf}
}

func (d *Dialer) Dial(endpoint string) (transport.Conn, *protocol.HandshakeResult, error) {
	raw, err := tls.Dial("tcp", endpoint, d.tlsConf)
	if err != nil {
		return nil, nil, err
	}
	// Handshake over TLS stream (tls.Conn implements io.ReadWriter)
	result, err := protocol.ClientHandshake(raw, d.clientID, d.vnetID, d.auth)
	if err != nil {
		raw.Close()
		return nil, nil, err
	}
	return newConn(raw, result.Keypair), result, nil
}
