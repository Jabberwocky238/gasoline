package trojan

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
	"wwww/transport/tcp"
	"wwww/transport/tls"
)

// go test -v ./transport/trojan -run TestTrojanTLS -timeout 5s
func TestTrojanTLS(t *testing.T) {
	certPEM, keyPEM, err := tls.GenerateSelfSignedCert("localhost")
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := tls.NewTLSServer(&tls.TLSServerConfig{
		ServerName: "localhost",
		CertPem:    []byte(certPEM),
		KeyPem:     []byte(keyPEM),
	})
	tlsClient := tls.NewTLSClient(&tls.TLSClientConfig{
		ServerName:         "localhost",
		SNI:                true,
		InsecureSkipVerify: true,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clientConfig := &ClientConfig{
		Password: "password",
	}
	serverConfig := &ServerConfig{
		Passwords:    []string{"password"},
		RedirectHost: "127.0.0.1",
		RedirectPort: 18080,
	}

	c := NewClient(ctx, tlsClient, clientConfig)
	s := NewServer(ctx, tlsServer, serverConfig)

	err = s.Listen("127.0.0.1", 18080)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1024)
	n := 0
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn := <-s.Accept()
		if conn == nil {
			return
		}
		defer conn.Close()
		n, err = conn.Read(buf)
	}()

	conn1, err := c.Dial("localhost:18080")
	if err != nil {
		t.Fatal(err)
	}
	conn1.Write([]byte("87654321"))
	wg.Wait()

	if string(buf[:n]) != "87654321" || n != 8 {
		t.Fatalf("data mismatch: got %q, expected %q", string(buf[:n]), "87654321")
	}
	defer conn1.Close()
}

// go test -v ./transport/trojan -run TestTrojanTCP -timeout 5s
func TestTrojanTCP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clientConfig := &ClientConfig{
		Password: "password",
	}
	serverConfig := &ServerConfig{
		Passwords:    []string{"password"},
		RedirectHost: "127.0.0.1",
		RedirectPort: 18080,
	}

	c := NewClient(ctx, tcp.NewTCPClient(), clientConfig)
	s := NewServer(ctx, tcp.NewTCPServer(), serverConfig)

	err := s.Listen("127.0.0.1", 18080)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	n := 0
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn := <-s.Accept()
		if conn == nil {
			return
		}
		defer conn.Close()
		n, err = conn.Read(buf)
	}()

	conn1, err := c.Dial("localhost:18080")
	if err != nil {
		t.Fatal(err)
	}
	conn1.Write([]byte("87654321"))
	wg.Wait()

	if string(buf[:n]) != "87654321" || n != 8 {
		t.Fatalf("data mismatch: got %q, expected %q", string(buf[:n]), "87654321")
	}
	defer conn1.Close()
}

// go test -v ./transport/trojan -run TestTrojanRedirect -timeout 5s
func TestTrojanRedirect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverConfig := &ServerConfig{
		Passwords:    []string{"password"}, // 服务器期望的密码
		RedirectHost: "127.0.0.1",
		RedirectPort: 18080, // 重定向到 HTTP 服务器
	}
	// 创建 HTTP 服务器作为重定向目标
	httpServer := &http.Server{
		Addr: "127.0.0.1:18080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}),
	}
	httpListener, err := net.Listen("tcp", "127.0.0.1:18080")
	if err != nil {
		t.Fatal(err)
	}
	defer httpListener.Close()

	// 启动 HTTP 服务器
	go func() {
		httpServer.Serve(httpListener)
	}()

	s := NewServer(ctx, tcp.NewTCPServer(), serverConfig)
	defer s.Close()

	// 启动 trojan 服务器
	if err := s.Listen("127.0.0.1", 18099); err != nil {
		t.Fatal(err)
	}

	// 等待服务器启动完成
	time.Sleep(100 * time.Millisecond)

	// 使用普通 TCP 连接发送 HTTP 请求（不是 trojan 客户端）
	// 这样服务器验证会失败（收到的是 HTTP 请求，不是 trojan 协议头），触发重定向
	conn1, err := net.Dial("tcp", "127.0.0.1:18099")
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()

	// 发送 HTTP GET 请求
	req, err := http.NewRequest("GET", "http://localhost:18099/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Write(conn1); err != nil {
		t.Fatalf("failed to write HTTP request: %v", err)
	}
	recvBuf := make([]byte, 1024)
	n, err := conn1.Read(recvBuf)
	if err != nil {
		t.Fatalf("failed to read HTTP response: %v", err)
	}

	response := string(recvBuf[:n])
	// 验证返回的是 HTTP 响应
	if !strings.HasPrefix(response, "HTTP/1.1 200 OK") {
		t.Fatalf("expected HTTP 200 OK response, got: %q", response)
	}
}
