package tlstransport

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

func generateSelfSignedCert(host string) (certPEM, keyPEM []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{host},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPEM, keyPEM, nil
}

func TestTLS(t *testing.T) {
	host := "127.0.0.1"
	port := 18081

	certPEM, keyPEM, err := generateSelfSignedCert(host)
	if err != nil {
		t.Fatal(err)
	}

	// 构建 RootCAs 以信任自签证书
	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM(certPEM); !ok {
		t.Fatal("failed to append self-signed cert to roots")
	}

	serverCfg := &TLSServerConfig{
		Host:    host,
		Port:    port,
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}
	server := NewTLSServer(serverCfg)
	if err := server.Listen(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	clientCfg := &TLSClientConfig{
		Endpoint: host + ":" + "18081",
		TLSConfig: &tls.Config{
			ServerName: host,
			RootCAs:    roots,
		},
	}
	client := NewTLSClient(clientCfg)
	defer client.Close()

	// 服务端：简单 echo 处理
	go func() {
		srvConn, err := server.Accept()
		if err != nil {
			return
		}
		defer func() { _ = srvConn.(interface{ Close() error }) }()
		// echo：从自身读并写回
		buf := make([]byte, 1024)
		n, err := srvConn.Read(buf)
		if err == nil && n > 0 {
			_, _ = srvConn.Write(buf[:n])
		}
	}()

	transportConn, err := client.Dial()
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1024)
	_, err = transportConn.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	rlen, err := transportConn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:rlen]) != "hello" {
		t.Fatalf("data mismatch: %s != %s", string(buf[:rlen]), "hello")
	}
}
