package quic

import (
	"context"
	"crypto/tls"

	"github.com/quic-go/quic-go"

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

func (l *Listener) Accept() (transport.Accepted, error) {
	conn, err := l.inner.Accept(context.Background())
	if err != nil {
		return transport.Accepted{}, err
	}
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		conn.CloseWithError(0, "stream accept failed")
		return transport.Accepted{}, err
	}

	auth, err := handshake.ServerHandshake(stream, l.mapper)
	if err != nil {
		conn.CloseWithError(0, "handshake failed")
		return transport.Accepted{}, err
	}
	return transport.Accepted{
		Conn: newConn(stream, conn.RemoteAddr().String()), VNI: auth.VNI, ClientPub: auth.ClientPub, Session: auth.Session,
		C2SKey: auth.C2SKey, S2CKey: auth.S2CKey,
	}, nil
}

func (l *Listener) Close() error { return l.inner.Close() }
func (l *Listener) Addr() string { return l.inner.Addr().String() }
