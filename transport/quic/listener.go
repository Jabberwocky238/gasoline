package quic

// QUIC transport requires github.com/quic-go/quic-go dependency.
// Add to go.mod: go get github.com/quic-go/quic-go
//
// Example usage:
//
//	ln, _ := quic.NewListener("0.0.0.0:443", auth, tlsConf)
//	conn, result, err := ln.Accept()

import (
	"context"
	"crypto/tls"

	"github.com/quic-go/quic-go"

	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/protocol/handshake"
	"github.com/jabberwocky238/gasoline/transport"
)

type Listener struct {
	inner    *quic.Listener
	resolver auth.AuthResolverFn
	routes   handshake.RouteResolverFn
}

func NewListener(addr string, resolver auth.AuthResolverFn, routes handshake.RouteResolverFn, tlsConf *tls.Config) (*Listener, error) {
	ln, err := quic.ListenAddr(addr, tlsConf, nil)
	if err != nil {
		return nil, err
	}
	return &Listener{inner: ln, resolver: resolver, routes: routes}, nil
}

func (l *Listener) Accept() (transport.Conn, *handshake.HandshakeResult, error) {
	conn, err := l.inner.Accept(context.Background())
	if err != nil {
		return nil, nil, err
	}
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		conn.CloseWithError(0, "stream accept failed")
		return nil, nil, err
	}

	result, err := handshake.ServerHandshake(stream, l.resolver, l.routes)
	if err != nil {
		conn.CloseWithError(0, "handshake failed")
		return nil, nil, err
	}

	return newConn(stream, conn.RemoteAddr().String()), result, nil
}

func (l *Listener) Close() error { return l.inner.Close() }
func (l *Listener) Addr() string { return l.inner.Addr().String() }
