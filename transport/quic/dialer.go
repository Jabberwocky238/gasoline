package quic

import (
	"context"
	"crypto/tls"

	"github.com/quic-go/quic-go"

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

func (d *Dialer) Dial(endpoint string) (transport.Conn, *handshake.HandshakeResult, error) {
	conn, err := quic.DialAddr(context.Background(), endpoint, d.tlsConf, nil)
	if err != nil {
		return nil, nil, err
	}
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		conn.CloseWithError(0, "stream open failed")
		return nil, nil, err
	}

	result, err := handshake.ClientHandshake(stream, &d.cfg, d.auth)
	if err != nil {
		conn.CloseWithError(0, "handshake failed")
		return nil, nil, err
	}

	return newConn(stream, conn.RemoteAddr().String()), result, nil
}
