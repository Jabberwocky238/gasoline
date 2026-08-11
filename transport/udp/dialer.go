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
	bootAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return transport.Dialed{}, err
	}
	// Bind an UNCONNECTED socket so the data plane can hop its destination at
	// runtime (PRD §5/§6) and receive replies from any server IP/port. The
	// handshake runs over the same socket targeting the bootstrap address.
	rawConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return transport.Dialed{}, err
	}
	_ = rawConn.SetReadBuffer(8 * 1024 * 1024)
	_ = rawConn.SetWriteBuffer(8 * 1024 * 1024)

	adapter := newClientStreamAdapterTo(rawConn, bootAddr)
	sess, err := handshake.ClientHandshake(adapter, d.cfg.VNI, d.id.Priv, d.id.Pub, d.id.ServerPub)
	if err != nil {
		rawConn.Close()
		return transport.Dialed{}, err
	}

	return transport.Dialed{Conn: newHoppingClientConn(rawConn, bootAddr), Session: sess}, nil
}
