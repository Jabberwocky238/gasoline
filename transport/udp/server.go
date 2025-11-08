package udp

import (
	"errors"
	"net"

	"context"
	"wwww/transport"
)

type UDPServer struct {
	bind     *net.UDPConn
	connChan chan transport.TransportConn
	conns    map[string]*UDPConn // 使用地址字符串作为键
	ctx      context.Context
	cancel   context.CancelFunc
}

func NewUDPServer() *UDPServer {
	return &UDPServer{
		connChan: make(chan transport.TransportConn, 1024),
		conns:    make(map[string]*UDPConn),
	}
}

func (t *UDPServer) Listen(host string, port int) error {
	ctx, cancel := context.WithCancel(context.Background())
	t.ctx = ctx
	t.cancel = cancel
	addr := net.UDPAddr{IP: net.ParseIP(host), Port: port}
	listener, err := net.ListenUDP("udp", &addr)
	if err != nil {
		return err
	}
	t.bind = listener
	go t.acceptLoop(&addr)
	return nil
}

func (t *UDPServer) acceptLoop(laddr *net.UDPAddr) {
	buf := make([]byte, 65535)
	for {
		n, raddr, err := t.bind.ReadFromUDP(buf)
		if err != nil {
			// 如果连接已关闭，退出循环
			if t.ctx.Err() != nil {
				return
			}
			continue
		}
		// 使用地址字符串作为键，确保相同地址的客户端使用同一个连接
		addrKey := raddr.String()
		if _, ok := t.conns[addrKey]; !ok {
			packetConn := net.PacketConn(t.bind)
			conn := NewUDPConn(laddr, raddr, packetConn)
			t.conns[addrKey] = conn
			t.connChan <- conn
		}
		// 复制数据到新的 slice，避免被下次读取覆盖
		data := make([]byte, n)
		copy(data, buf[:n])
		t.conns[addrKey].packetChan <- data
	}
}

func (t *UDPServer) Accept() (transport.TransportConn, error) {
	select {
	case conn := <-t.connChan:
		return conn, nil
	case <-t.ctx.Done():
		return nil, errors.New("server closed")
	}
}

func (t *UDPServer) Close() error {
	t.cancel()
	return t.bind.Close()
}
