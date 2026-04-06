package udp

import (
	"net"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/transport"
)

type Dialer struct {
	clientID [16]byte
	auth     protocol.ClientAuthenticator
}

func NewDialer(clientID [16]byte, auth protocol.ClientAuthenticator) *Dialer {
	return &Dialer{clientID: clientID, auth: auth}
}

func (d *Dialer) Dial(endpoint string) (transport.Conn, *protocol.HandshakeResult, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return nil, nil, err
	}
	rawConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, nil, err
	}

	// Handshake over stream adapter (buffers datagrams for io.ReadFull)
	adapter := newClientStreamAdapter(rawConn)
	result, err := protocol.ClientHandshake(adapter, d.clientID, d.auth)
	if err != nil {
		rawConn.Close()
		return nil, nil, err
	}

	// After handshake: switch to datagram + AEAD mode
	return newClientConn(rawConn, result.Keypair), result, nil
}
