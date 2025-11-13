package trojan

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// go test -v ./transport/trojan -run TestRedirector -timeout 5s
func TestRedirector(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	redir := NewRedirector(ctx)

	// 测试 nil 参数处理
	redir.Redirect(&Redirection{
		Dial:        nil,
		RedirectTo:  nil,
		InboundConn: nil,
	})
	var fakeAddr net.Addr
	var fakeConn net.Conn
	redir.Redirect(&Redirection{
		Dial:        nil,
		RedirectTo:  fakeAddr,
		InboundConn: fakeConn,
	})
	redir.Redirect(&Redirection{
		Dial:        nil,
		RedirectTo:  nil,
		InboundConn: fakeConn,
	})
	redir.Redirect(&Redirection{
		Dial:        nil,
		RedirectTo:  fakeAddr,
		InboundConn: nil,
	})

	// 创建 HTTP 服务器作为重定向目标
	httpServer := &http.Server{
		Addr: "127.0.0.1:0", // 自动分配端口
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}),
	}
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer httpListener.Close()

	httpAddr := httpListener.Addr().(*net.TCPAddr)
	go httpServer.Serve(httpListener)

	// 创建用于接收重定向连接的监听器
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// 客户端连接到监听器
	conn1, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()

	// 接受连接
	conn2, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}

	// 将 conn2 重定向到 HTTP 服务器
	redirAddr, err := net.ResolveTCPAddr("tcp", httpAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	redir.Redirect(&Redirection{
		Dial:        nil,
		RedirectTo:  redirAddr,
		InboundConn: conn2,
	})

	// 等待重定向建立
	time.Sleep(100 * time.Millisecond)

	// 通过 conn1 发送 HTTP 请求
	req, err := http.NewRequest("GET", "http://localhost/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Write(conn1); err != nil {
		t.Fatal(err)
	}

	// 读取响应
	conn1.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn1.Read(buf)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	response := string(buf[:n])
	fmt.Println("Response:", response)

	if !strings.HasPrefix(response, "HTTP/1.1 200 OK") {
		t.Errorf("expected HTTP 200 OK, got: %s", response)
	}
}
