package tcp

import (
	"net"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/protocol/handshake"
	"github.com/jabberwocky238/gasoline/transport"
)

type Dialer struct {
	cfg  protocol.PresetSessionConfig
	auth auth.ClientAuthenticator
}

func NewDialer(cfg protocol.PresetSessionConfig, auth auth.ClientAuthenticator) *Dialer {
	return &Dialer{cfg: cfg, auth: auth}
}

func (d *Dialer) Dial(endpoint string) (transport.Conn, *protocol.SessionContext, error) {
	raw, err := net.Dial("tcp", endpoint)
	if err != nil {
		return nil, nil, err
	}
	sc, err := handshake.ClientHandshake(raw, d.cfg.VNI, d.cfg.CID, d.auth)
	if err != nil {
		raw.Close()
		return nil, nil, err
	}
	return newConn(raw), sc, nil
}
