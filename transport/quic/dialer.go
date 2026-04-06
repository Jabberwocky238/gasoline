package quic

// QUIC transport requires github.com/quic-go/quic-go dependency.
// Add to go.mod: go get github.com/quic-go/quic-go
//
// Example usage:
//
//	dialer := quic.NewDialer(clientID, auth, tlsConf)
//	conn, result, err := dialer.Dial("server:443")

// TODO: Uncomment when quic-go is added as a dependency.

/*
import (
	"context"
	"crypto/tls"

	"github.com/quic-go/quic-go"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/transport"
)

type Dialer struct {
	clientID [16]byte
	auth     protocol.ClientAuthenticator
	tlsConf  *tls.Config
}

func NewDialer(clientID [16]byte, auth protocol.ClientAuthenticator, tlsConf *tls.Config) *Dialer {
	return &Dialer{clientID: clientID, auth: auth, tlsConf: tlsConf}
}

func (d *Dialer) Dial(endpoint string) (transport.Conn, *protocol.HandshakeResult, error) {
	conn, err := quic.DialAddr(context.Background(), endpoint, d.tlsConf, nil)
	if err != nil {
		return nil, nil, err
	}
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		conn.CloseWithError(0, "stream open failed")
		return nil, nil, err
	}

	// Handshake over QUIC stream (implements io.ReadWriter)
	result, err := protocol.ClientHandshake(stream, d.clientID, d.auth)
	if err != nil {
		conn.CloseWithError(0, "handshake failed")
		return nil, nil, err
	}

	return newConn(stream, result.Keypair, conn.RemoteAddr().String()), result, nil
}
*/
