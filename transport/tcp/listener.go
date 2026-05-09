package tcp

import (
	"net"

	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/protocol/handshake"
	"github.com/jabberwocky238/gasoline/transport"
)

type Listener struct {
	inner    net.Listener
	resolver auth.AuthResolver
}

func NewListener(addr string, resolver auth.AuthResolver) (*Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Listener{inner: ln, resolver: resolver}, nil
}

func (l *Listener) Accept() (transport.Conn, *handshake.HandshakeResult, error) {
	raw, err := l.inner.Accept()
	if err != nil {
		return nil, nil, err
	}
	// Handshake over raw TCP stream
	result, err := handshake.ServerHandshake(raw, l.resolver)
	if err != nil {
		raw.Close()
		return nil, nil, err
	}
	return newConn(raw), result, nil
}

func (l *Listener) Close() error { return l.inner.Close() }
func (l *Listener) Addr() string { return l.inner.Addr().String() }
