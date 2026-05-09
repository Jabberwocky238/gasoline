package tcp

import (
	"net"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/protocol/handshake"
	"github.com/jabberwocky238/gasoline/transport"
)

type Dialer struct {
	cfg  protocol.PreassignedSessionConfig
	auth auth.ClientAuthenticator
}

func NewDialer(cfg protocol.PreassignedSessionConfig, auth auth.ClientAuthenticator) *Dialer {
	return &Dialer{cfg: cfg, auth: auth}
}

func (d *Dialer) Dial(endpoint string) (transport.Conn, *handshake.HandshakeResult, error) {
	raw, err := net.Dial("tcp", endpoint)
	if err != nil {
		return nil, nil, err
	}
	result, err := handshake.ClientHandshake(raw, &d.cfg, d.auth)
	if err != nil {
		raw.Close()
		return nil, nil, err
	}
	return newConn(raw), result, nil
}
