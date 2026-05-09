package tls

import (
	"crypto/tls"
	"net"

	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/protocol/handshake"
	"github.com/jabberwocky238/gasoline/transport"
)

type Listener struct {
	inner    net.Listener
	resolver auth.AuthResolverFn
	routes   handshake.RouteResolverFn
}

func NewListener(addr string, resolver auth.AuthResolverFn, routes handshake.RouteResolverFn, tlsConf *tls.Config) (*Listener, error) {
	ln, err := tls.Listen("tcp", addr, tlsConf)
	if err != nil {
		return nil, err
	}
	return &Listener{inner: ln, resolver: resolver, routes: routes}, nil
}

func (l *Listener) Accept() (transport.Conn, *handshake.HandshakeResult, error) {
	raw, err := l.inner.Accept()
	if err != nil {
		return nil, nil, err
	}
	tlsConn := raw.(*tls.Conn)
	// TLS handshake happens automatically on first Read/Write,
	// but we do it explicitly to catch errors early.
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, nil, err
	}
	// Gasoline handshake over TLS stream
	result, err := handshake.ServerHandshake(tlsConn, l.resolver, l.routes)
	if err != nil {
		tlsConn.Close()
		return nil, nil, err
	}
	return newConn(tlsConn), result, nil
}

func (l *Listener) Close() error { return l.inner.Close() }
func (l *Listener) Addr() string { return l.inner.Addr().String() }
