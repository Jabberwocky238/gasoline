package tls

import (
	"context"
	"crypto/tls"
	"wwww/transport"
)

type TLSClient struct {
	cfg           *TLSClientConfig
	transportConn *TransportTLSConn
	ctx           context.Context
	cancel        context.CancelFunc
}

func NewTLSClient(ctx context.Context) transport.TransportClient {
	ctx, cancel := context.WithCancel(ctx)
	cfg := ctx.Value("cfg").(*TLSClientConfig)
	return &TLSClient{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
	}
}

func (t *TLSClient) Dial(endpoint string) (transport.TransportConn, error) {
	ctx, cancel := context.WithCancel(context.Background())
	t.ctx = ctx
	t.cancel = cancel

	tlsCfg := t.cfg.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{
			InsecureSkipVerify: t.cfg.InsecureSkipVerify,
			ServerName:         t.cfg.ServerName,
			RootCAs:            t.cfg.RootCAs,
			Certificates:       t.cfg.Certificates,
		}
	}

	conn, err := tls.Dial("tcp", endpoint, tlsCfg)
	if err != nil {
		t.cancel()
		return nil, err
	}
	t.transportConn = conn
	return t.transportConn, nil
}

func (t *TLSClient) Close() error {
	if t.cancel != nil {
		t.cancel()
	}
	if t.transportConn != nil {
		return t.transportConn.Close()
	}
	return nil
}
