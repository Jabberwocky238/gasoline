package udp

import (
	"context"
	"net"
	"strconv"
	"wwww/transport"
)

type UDPClientConfig struct {
}

type UDPClient struct {
	cfg  *UDPClientConfig
	conn *UDPConn
}

func NewUDPClient(ctx context.Context) transport.TransportClient {
	cfg, ok := ctx.Value("cfg").(*UDPClientConfig)
	if !ok {
		cfg = &UDPClientConfig{}
	}
	return &UDPClient{
		cfg: cfg,
	}
}

func (t *UDPClient) Dial(endpoint string) (transport.TransportConn, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, err
	}
	rportInt, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	// 客户端不需要绑定到特定端口，让系统自动分配可用端口
	// 使用 nil 作为 laddr 让系统自动选择本地地址和端口
	raddr := &net.UDPAddr{IP: net.ParseIP(host), Port: rportInt}
	packetConn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	// 获取实际分配的本地地址
	actualLaddr := packetConn.LocalAddr().(*net.UDPAddr)
	conn := NewUDPConn(actualLaddr, raddr, packetConn)
	t.conn = conn
	return conn, nil
}

func (t *UDPClient) Close() error {
	return t.conn.Close()
}
