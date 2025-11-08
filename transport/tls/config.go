package tls

import (
	"crypto/tls"
	"crypto/x509"
)

type TLSServerConfig struct {
	// 可直接传入 tls.Config；若为 nil 则使用 CertPEM/KeyPEM/ClientCAs 构造
	TLSConfig *tls.Config

	// 便捷字段：用于快速构造自签/内存证书
	CertPEM []byte
	KeyPEM  []byte

	// 可选：双向 TLS 时的客户端 CA
	ClientCAs *x509.CertPool
	// 是否要求客户端证书
	RequireClientCert bool
}

type TLSClientConfig struct {
	Endpoint string // host:port

	// 直接传入 tls.Config；若为 nil 则使用下列便捷字段构造
	TLSConfig *tls.Config

	// 便捷字段
	InsecureSkipVerify bool
	ServerName         string
	RootCAs            *x509.CertPool
	Certificates       []tls.Certificate // 客户端证书（可选）
}
