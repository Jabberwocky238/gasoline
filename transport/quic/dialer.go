package quic

import (
	"context"
	"crypto/tls"

	"github.com/quic-go/quic-go"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/handshake"
	"github.com/jabberwocky238/gasoline/transport"
)

type Dialer struct {
	cfg     protocol.PresetSessionConfig
	id      transport.ClientIdentity
	tlsConf *tls.Config
}

func NewDialer(cfg protocol.PresetSessionConfig, id transport.ClientIdentity, tlsConf *tls.Config) *Dialer {
	return &Dialer{cfg: cfg, id: id, tlsConf: tlsConf}
}

func (d *Dialer) Dial(endpoint string) (transport.Conn, *protocol.SessionContext, error) {
	conn, err := quic.DialAddr(context.Background(), endpoint, d.tlsConf, nil)
	if err != nil {
		return nil, nil, err
	}
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		conn.CloseWithError(0, "stream open failed")
		return nil, nil, err
	}

	sc, _, err := handshake.ClientHandshake(stream, d.cfg.VNI, d.id.Priv, d.id.Pub, d.id.ServerPub)
	if err != nil {
		conn.CloseWithError(0, "handshake failed")
		return nil, nil, err
	}

	return newConn(stream, conn.RemoteAddr().String()), sc, nil
}
