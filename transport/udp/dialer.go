package udp

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
	udpAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return nil, nil, err
	}
	rawConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, nil, err
	}
	_ = rawConn.SetReadBuffer(8 * 1024 * 1024)
	_ = rawConn.SetWriteBuffer(8 * 1024 * 1024)

	adapter := newClientStreamAdapter(rawConn)
	sc, err := handshake.ClientHandshake(adapter, d.cfg.VNI, d.cfg.CID, d.auth)
	if err != nil {
		rawConn.Close()
		return nil, nil, err
	}

	return newClientConn(rawConn), sc, nil
}
