package quic

// QUIC transport requires github.com/quic-go/quic-go dependency.
// Add to go.mod: go get github.com/quic-go/quic-go
//
// Example usage:
//
//	ln, _ := quic.NewListener("0.0.0.0:443", auth, configFn, tlsConf)
//	conn, result, err := ln.Accept()

// TODO: Uncomment when quic-go is added as a dependency.

/*
import (
	"context"
	"crypto/tls"

	"github.com/quic-go/quic-go"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/transport"
)

type Listener struct {
	inner    *quic.Listener
	auth     protocol.ServerAuthenticator
	configFn protocol.ConfigFunc
}

func NewListener(addr string, auth protocol.ServerAuthenticator, configFn protocol.ConfigFunc, tlsConf *tls.Config) (*Listener, error) {
	ln, err := quic.ListenAddr(addr, tlsConf, nil)
	if err != nil {
		return nil, err
	}
	return &Listener{inner: ln, auth: auth, configFn: configFn}, nil
}

func (l *Listener) Accept() (transport.Conn, *protocol.HandshakeResult, error) {
	conn, err := l.inner.Accept(context.Background())
	if err != nil {
		return nil, nil, err
	}
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		conn.CloseWithError(0, "stream accept failed")
		return nil, nil, err
	}

	result, err := protocol.ServerHandshake(stream, l.auth, l.configFn)
	if err != nil {
		conn.CloseWithError(0, "handshake failed")
		return nil, nil, err
	}

	return newConn(stream, result.Keypair, conn.RemoteAddr().String()), result, nil
}

func (l *Listener) Close() error { return l.inner.Close() }
func (l *Listener) Addr() string { return l.inner.Addr().String() }
*/
