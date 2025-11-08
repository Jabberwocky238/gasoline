package tcp

import (
	"errors"
	"fmt"
	"net"

	"context"
	"wwww/transport"
)

type TCPServer struct {
	listener *net.TCPListener

	connChan chan transport.TransportConn
	ctx      context.Context
	cancel   context.CancelFunc
}

func NewTCPServer() transport.TransportServer {
	return &TCPServer{
		connChan: make(chan transport.TransportConn, 1024),
	}
}

func (t *TCPServer) Listen(host string, port int) error {
	ctx, cancel := context.WithCancel(context.Background())
	t.ctx = ctx
	t.cancel = cancel
	listener, err := net.Listen("tcp4", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return err
	}
	t.listener = listener.(*net.TCPListener)
	go t.acceptLoop()
	return nil
}

func (t *TCPServer) acceptLoop() (net.Conn, error) {
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			return nil, err
		}
		t.connChan <- conn
	}
}

func (t *TCPServer) Accept() (transport.TransportConn, error) {
	select {
	case conn := <-t.connChan:
		// 优化TCP连接性能
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetNoDelay(true)                // 关闭Nagle算法，减少延迟
			tcpConn.SetReadBuffer(4 * 1024 * 1024)  // 4MB读缓冲区
			tcpConn.SetWriteBuffer(4 * 1024 * 1024) // 4MB写缓冲区
		}
		return conn, nil
	case <-t.ctx.Done():
		return nil, errors.New("server closed")
	}
}

func (t *TCPServer) Close() error {
	t.cancel()
	return t.listener.Close()
}
