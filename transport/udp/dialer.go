package udp

import (
	"net"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/handshake"
	"github.com/jabberwocky238/gasoline/transport"
)

type Dialer struct {
	cfg protocol.PresetSessionConfig
	id  transport.ClientIdentity
}

func NewDialer(cfg protocol.PresetSessionConfig, id transport.ClientIdentity) *Dialer {
	return &Dialer{cfg: cfg, id: id}
}

func (d *Dialer) Dial(endpoint string) (transport.Dialed, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return transport.Dialed{}, err
	}
	rawConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return transport.Dialed{}, err
	}
	_ = rawConn.SetReadBuffer(8 * 1024 * 1024)
	_ = rawConn.SetWriteBuffer(8 * 1024 * 1024)

	adapter := newClientStreamAdapter(rawConn)
	sess, err := handshake.ClientHandshake(adapter, d.cfg.VNI, d.id.Priv, d.id.Pub, d.id.ServerPub)
	if err != nil {
		rawConn.Close()
		return transport.Dialed{}, err
	}

	return transport.Dialed{Conn: newClientConn(rawConn), Session: sess}, nil
}
