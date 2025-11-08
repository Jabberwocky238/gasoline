package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"wwww/transport"
)

type TLSServer struct {
	cfg      *TLSServerConfig
	listener net.Listener

	connChan chan transport.TransportConn
	ctx      context.Context
	cancel   context.CancelFunc
}

func NewTLSServer(ctx context.Context) *TLSServer {
	ctx, cancel := context.WithCancel(ctx)
	cfg := ctx.Value("cfg").(*TLSServerConfig)
	return &TLSServer{
		cfg:      cfg,
		ctx:      ctx,
		cancel:   cancel,
		connChan: make(chan transport.TransportConn, 1024),
	}
}

func (t *TLSServer) Listen(host string, port int) error {
	ctx, cancel := context.WithCancel(context.Background())
	t.ctx = ctx
	t.cancel = cancel

	baseListener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return err
	}

	tlsCfg := t.cfg.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
		if len(t.cfg.CertPEM) > 0 && len(t.cfg.KeyPEM) > 0 {
			cert, err := tls.X509KeyPair(t.cfg.CertPEM, t.cfg.KeyPEM)
			if err != nil {
				baseListener.Close()
				return err
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
		if t.cfg.ClientCAs != nil {
			tlsCfg.ClientCAs = t.cfg.ClientCAs
			if t.cfg.RequireClientCert {
				tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
			}
		}
	}

	t.listener = tls.NewListener(baseListener, tlsCfg)
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

func (t *TLSServer) Accept() (transport.TransportConn, error) {
	select {
	case conn := <-t.connChan:
		return conn, nil
	case <-t.ctx.Done():
		return nil, errors.New("server closed")
	}
}

func (t *TLSServer) Close() error {
	if t.cancel != nil {
		t.cancel()
	}
	if t.listener != nil {
		return t.listener.Close()
	}
	return nil
}
