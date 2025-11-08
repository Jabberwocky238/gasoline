package tcp

import (
	"net"
	"wwww/transport"
)

type TCPClient struct {
	conn *net.TCPConn
}

func NewTCPClient() transport.TransportClient {
	return &TCPClient{
		conn: nil,
	}
}

func (t *TCPClient) Dial(endpoint string) (transport.TransportConn, error) {
	conn, err := net.Dial("tcp", endpoint)
	if err != nil {
		return nil, err
	}
	// 优化TCP连接性能
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)                // 关闭Nagle算法，减少延迟，避免等待ACK
		tcpConn.SetReadBuffer(8 * 1024 * 1024)  // 8MB读缓冲区
		tcpConn.SetWriteBuffer(8 * 1024 * 1024) // 8MB写缓冲区
	}
	t.conn = conn.(*net.TCPConn)
	return conn, nil
}

func (t *TCPClient) Close() error {
	return t.conn.Close()
}
