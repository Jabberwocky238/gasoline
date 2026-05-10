package tls

import (
	"crypto/tls"
	"net"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/handshake"
	"github.com/jabberwocky238/gasoline/transport"
)

type Listener struct {
	inner  net.Listener
	mapper handshake.VNIMapperFn
}

func NewListener(addr string, mapper handshake.VNIMapperFn, tlsConf *tls.Config) (*Listener, error) {
	ln, err := tls.Listen("tcp", addr, tlsConf)
	if err != nil {
		return nil, err
	}
	return &Listener{inner: ln, mapper: mapper}, nil
}

func (l *Listener) Accept() (transport.Conn, *protocol.SessionContext, error) {
	raw, err := l.inner.Accept()
	if err != nil {
		return nil, nil, err
	}
	tlsConn := raw.(*tls.Conn)
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, nil, err
	}
	sc, err := handshake.ServerHandshake(tlsConn, l.mapper)
	if err != nil {
		tlsConn.Close()
		return nil, nil, err
	}
	return newConn(tlsConn), sc, nil
}

func (l *Listener) Close() error { return l.inner.Close() }
func (l *Listener) Addr() string { return l.inner.Addr().String() }
