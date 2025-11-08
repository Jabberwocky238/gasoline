package udp

import (
	"net"
)

// 因为UDP无状态，但是我们需要复用链接，所以需要记录当前链接的对端地址
type UDPConn struct {
	laddr      *net.UDPAddr
	raddr      *net.UDPAddr
	conn       net.PacketConn
	packetChan chan []byte
}

func NewUDPConn(laddr *net.UDPAddr, raddr *net.UDPAddr, conn net.PacketConn) *UDPConn {
	return &UDPConn{
		laddr:      laddr,
		raddr:      raddr,
		conn:       conn,
		packetChan: make(chan []byte, 1024),
	}
}

func (c *UDPConn) Read(b []byte) (n int, err error) {
	buf := <-c.packetChan
	copy(b, buf)
	return len(buf), nil
}

func (c *UDPConn) Write(b []byte) (n int, err error) {
	// 如果 conn 是已连接的 UDPConn，使用 Write 方法
	// 如果是未连接的 PacketConn，使用 WriteTo 方法
	if udpConn, ok := c.conn.(*net.UDPConn); ok {
		return udpConn.Write(b)
	}
	return c.conn.WriteTo(b, c.raddr)
}

func (c *UDPConn) Close() error {
	return c.conn.Close()
}

func (c *UDPConn) LocalAddr() net.Addr {
	return c.laddr
}

func (c *UDPConn) RemoteAddr() net.Addr {
	return c.raddr
}
