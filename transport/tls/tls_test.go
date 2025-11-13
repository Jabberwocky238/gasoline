package tls

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// go test -v ./transport/tls -run TestTLSWithFile -timeout 5s
func TestTLSWithFile(t *testing.T) {
	host := "127.0.0.1"
	port := 18081

	var certPEM, keyPEM []byte
	var err error
	pwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	// read from file
	certPEM, err = os.ReadFile(filepath.Join(pwd, "../..", "samples", "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err = os.ReadFile(filepath.Join(pwd, "../..", "samples", "key.pem"))
	if err != nil {
		t.Fatal(err)
	}

	serverCfg := &TLSServerConfig{
		CertPem: certPEM,
		KeyPem:  keyPEM,
	}
	server := NewTLSServer(serverCfg)
	if err := server.Listen(host, port); err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	clientCfg := &TLSClientConfig{
		ServerName:         host,
		SNI:                true,
		InsecureSkipVerify: true, // 跳过自签名证书验证
	}
	client := NewTLSClient(clientCfg)

	// 服务端：简单 echo 处理
	go func() {
		srvConn := <-server.Accept()
		defer srvConn.Close()
		// echo：从自身读并写回
		buf := make([]byte, 1024)
		n, err := srvConn.Read(buf)
		if err == nil && n > 0 {
			_, _ = srvConn.Write(buf[:n])
		}
	}()

	transportConn, err := client.Dial(host + ":" + "18081")
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

// go test -v ./transport/tls -run TestTLSWithSelfSignedCert -timeout 5s
func TestTLSWithSelfSignedCert(t *testing.T) {
	host := "127.0.0.1"
	port := 18081

	certPEM, keyPEM, err := GenerateSelfSignedCert("localhost")
	if err != nil {
		t.Fatal(err)
	}
	serverCfg := &TLSServerConfig{
		ServerName: "localhost",
		CertPem:    certPEM,
		KeyPem:     keyPEM,
	}
	server := NewTLSServer(serverCfg)
	if err := server.Listen(host, port); err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	clientCfg := &TLSClientConfig{
		ServerName:         "localhost",
		SNI:                true,
		InsecureSkipVerify: true, // 跳过自签名证书验证
	}
	client := NewTLSClient(clientCfg)

	// 服务端：简单 echo 处理
	go func() {
		srvConn := <-server.Accept()
		if srvConn == nil {
			return
		}
		defer srvConn.Close()
		// echo：从自身读并写回
		buf := make([]byte, 1024)
		n, err := srvConn.Read(buf)
		if err == nil && n > 0 {
			_, _ = srvConn.Write(buf[:n])
		}
	}()

	// 等待服务器启动完成
	time.Sleep(100 * time.Millisecond)

	transportConn, err := client.Dial(host + ":" + "18081")
	if err != nil {
		t.Fatal(err)
	}
	defer transportConn.Close()

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
