package tcp

import (
	"net"
	"wwww/transport"
)

type TCPClient struct{}

func NewTCPClient() *TCPClient {
	return &TCPClient{}
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
	return conn, nil
}
