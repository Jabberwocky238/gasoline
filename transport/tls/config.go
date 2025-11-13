package tls

import "crypto/tls"

type TLSServerConfig struct {
	ServerName string
	KeyPem     []byte
	CertPem    []byte
}

func (c *TLSServerConfig) ToTlsConfig() (*tls.Config, error) {
	cfg := &tls.Config{}

	if len(c.CertPem) > 0 && len(c.KeyPem) > 0 {
		cert, err := tls.X509KeyPair(c.CertPem, c.KeyPem)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	if c.ServerName != "" {
		cfg.ServerName = c.ServerName
	}

	return cfg, nil
}

type TLSClientConfig struct {
	ServerName         string
	SNI                bool
	InsecureSkipVerify bool
}

func (c *TLSClientConfig) ToTlsConfig() *tls.Config {
	cfg := &tls.Config{
		InsecureSkipVerify: c.InsecureSkipVerify,
	}

	// 如果 SNI 为 true，设置 ServerName（用于 SNI 扩展和证书验证）
	// 如果 SNI 为 false，不设置 ServerName（禁用 SNI）
	if c.SNI && c.ServerName != "" {
		cfg.ServerName = c.ServerName
	}

	return cfg
}
