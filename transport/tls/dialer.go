package tls

import (
	"crypto/tls"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/protocol/handshake"
	"github.com/jabberwocky238/gasoline/transport"
)

type Dialer struct {
	cfg     protocol.PresetSessionConfig
	auth    auth.ClientAuthenticator
	tlsConf *tls.Config
}

func NewDialer(cfg protocol.PresetSessionConfig, auth auth.ClientAuthenticator, tlsConf *tls.Config) *Dialer {
	return &Dialer{cfg: cfg, auth: auth, tlsConf: tlsConf}
}

func (d *Dialer) Dial(endpoint string) (transport.Conn, *protocol.SessionContext, error) {
	raw, err := tls.Dial("tcp", endpoint, d.tlsConf)
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
