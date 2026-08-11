package quic

import (
	"context"
	"crypto/tls"

	"github.com/quic-go/quic-go"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/handshake"
	"github.com/jabberwocky238/gasoline/transport"
)

type Listener struct {
	inner  *quic.Listener
	mapper handshake.VNIMapperFn
}

func NewListener(addr string, mapper handshake.VNIMapperFn, tlsConf *tls.Config) (*Listener, error) {
	ln, err := quic.ListenAddr(addr, tlsConf, nil)
	if err != nil {
		return nil, err
	}
	return &Listener{inner: ln, mapper: mapper}, nil
}

func (l *Listener) Accept() (transport.Conn, *protocol.SessionContext, error) {
	conn, err := l.inner.Accept(context.Background())
	if err != nil {
		return nil, nil, err
	}
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		conn.CloseWithError(0, "stream accept failed")
		return nil, nil, err
	}

	sc, _, _, err := handshake.ServerHandshake(stream, l.mapper)
	if err != nil {
		conn.CloseWithError(0, "handshake failed")
		return nil, nil, err
	}
	return newConn(stream, conn.RemoteAddr().String()), sc, nil
}

func (l *Listener) Close() error { return l.inner.Close() }
func (l *Listener) Addr() string { return l.inner.Addr().String() }
