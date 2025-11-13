package tls

import (
	"crypto/tls"
	"wwww/transport"
)

type TLSClient struct {
	cfg           *TLSClientConfig
	tlsCfg        *tls.Config
	transportConn *TransportTLSConn
}

func NewTLSClient(cfg *TLSClientConfig) transport.TransportClient {
	tlsCfg := cfg.ToTlsConfig()
	return &TLSClient{
		cfg:           cfg,
		tlsCfg:        tlsCfg,
		transportConn: nil,
	}
}

func (t *TLSClient) Dial(endpoint string) (transport.TransportConn, error) {
	conn, err := tls.Dial("tcp", endpoint, t.tlsCfg)
	if err != nil {
		return nil, err
	}
	t.transportConn = conn
	return t.transportConn, nil
}

func (t *TLSClient) Close() error {
	if t.transportConn != nil {
		return t.transportConn.Close()
	}
	return nil
}
