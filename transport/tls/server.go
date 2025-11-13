package tls

import (
	"crypto/tls"
	"fmt"
	"net"

	"wwww/transport"
)

type TLSServer struct {
	cfg    *TLSServerConfig
	tlsCfg *tls.Config

	listener net.Listener

	connChan chan transport.TransportConn
}

func NewTLSServer(cfg *TLSServerConfig) *TLSServer {
	tlsCfg, err := cfg.ToTlsConfig()
	if err != nil {
		return nil
	}
	return &TLSServer{
		cfg:      cfg,
		tlsCfg:   tlsCfg,
		connChan: make(chan transport.TransportConn, 1024),
	}
}

func (t *TLSServer) Listen(host string, port int) error {
	baseListener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return err
	}
	t.listener = tls.NewListener(baseListener, t.tlsCfg)
	go t.acceptLoop()
	return nil
}

func (t *TLSServer) acceptLoop() (net.Conn, error) {
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			return nil, err
		}
		t.connChan <- conn
	}
}

func (t *TLSServer) Accept() <-chan transport.TransportConn {
	return t.connChan
}

func (t *TLSServer) Close() error {
	close(t.connChan)
	if t.listener != nil {
		return t.listener.Close()
	}
	return nil
}
