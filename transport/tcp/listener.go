package tcp

import (
	"net"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/handshake"
	"github.com/jabberwocky238/gasoline/transport"
)

type Listener struct {
	inner  net.Listener
	mapper handshake.VNIMapperFn
}

func NewListener(addr string, mapper handshake.VNIMapperFn) (*Listener, error) {
	ln, err := net.Listen("tcp", addr)
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
	sc, err := handshake.ServerHandshake(raw, l.mapper)
	if err != nil {
		raw.Close()
		return nil, nil, err
	}
	return newConn(raw), sc, nil
}

func (l *Listener) Close() error { return l.inner.Close() }
func (l *Listener) Addr() string { return l.inner.Addr().String() }
