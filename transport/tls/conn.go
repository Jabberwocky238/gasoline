package tlstransport

import (
	"crypto/tls"
	"net"
)

type TransportTLSConn struct {
	conn *tls.Conn
}

func (t *TransportTLSConn) Write(p []byte) (int, error) {
	return t.conn.Write(p)
}

func (t *TransportTLSConn) Read(p []byte) (int, error) {
	return t.conn.Read(p)
}

func (t *TransportTLSConn) LocalAddr() net.Addr {
	return t.conn.LocalAddr()
}

func (t *TransportTLSConn) RemoteAddr() net.Addr {
	return t.conn.RemoteAddr()
}

func (t *TransportTLSConn) Close() error {
	return t.conn.Close()
}
