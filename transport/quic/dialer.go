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

func (d *Dialer) Dial(endpoint string) (transport.Dialed, error) {
	conn, err := quic.DialAddr(context.Background(), endpoint, d.tlsConf, nil)
	if err != nil {
		return transport.Dialed{}, err
	}
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		conn.CloseWithError(0, "stream open failed")
		return transport.Dialed{}, err
	}

	sess, err := handshake.ClientHandshake(stream, d.cfg.VNI, d.id.Priv, d.id.Pub, d.id.ServerPub)
	if err != nil {
		conn.CloseWithError(0, "handshake failed")
		return transport.Dialed{}, err
	}

	// Hopping-capable: retain the tls config + connection so the client can hop
	// by re-dialing a fresh QUIC connection (PRD §5.4.4).
	return transport.Dialed{Conn: newHoppingClientConn(stream, conn, d.tlsConf), Session: sess}, nil
}
