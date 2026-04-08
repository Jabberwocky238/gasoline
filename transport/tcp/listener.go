package tcp

import (
	"net"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport"
)

type Listener struct {
	inner    net.Listener
	resolver auth.AuthResolver
	configFn protocol.ConfigFunc
}

func NewListener(addr string, resolver auth.AuthResolver, configFn protocol.ConfigFunc) (*Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Listener{inner: ln, resolver: resolver, configFn: configFn}, nil
}

func (l *Listener) Accept() (transport.Conn, *protocol.HandshakeResult, error) {
	raw, err := l.inner.Accept()
	if err != nil {
		return nil, nil, err
	}
	// Handshake over raw TCP stream
	result, err := protocol.ServerHandshake(raw, l.resolver, l.configFn)
	if err != nil {
		raw.Close()
		return nil, nil, err
	}
	return newConn(raw, result.Keypair), result, nil
}

func (l *Listener) Close() error { return l.inner.Close() }
func (l *Listener) Addr() string { return l.inner.Addr().String() }
