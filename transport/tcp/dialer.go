package tcp

import (
	"net"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport"
)

type Dialer struct {
	clientID [16]byte
	auth     auth.ClientAuthenticator
}

func NewDialer(clientID [16]byte, auth auth.ClientAuthenticator) *Dialer {
	return &Dialer{clientID: clientID, auth: auth}
}

func (d *Dialer) Dial(endpoint string) (transport.Conn, *protocol.HandshakeResult, error) {
	raw, err := net.Dial("tcp", endpoint)
	if err != nil {
		return nil, nil, err
	}
	// Handshake over raw TCP stream (net.Conn implements io.ReadWriter)
	result, err := protocol.ClientHandshake(raw, d.clientID, d.auth)
	if err != nil {
		raw.Close()
		return nil, nil, err
	}
	return newConn(raw, result.Keypair), result, nil
}
