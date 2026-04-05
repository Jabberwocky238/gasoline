package udp

import (
	"net"

	"github.com/jabberwocky238/gasoline/common"
)

//	type Packet interface {
//		Data() []byte
//		Metadata() *Metadata
//	}
type TransportUDPPacket struct {
	data     []byte
	metadata *common.Metadata
}

func (p *TransportUDPPacket) Metadata() *common.Metadata {
	return p.metadata
}

func (p *TransportUDPPacket) Data() []byte {
	return p.data
}

//	type Conn interface {
//		Write(Packet) error
//		Read() (Packet, error)
//		Close() error
//	}
type TransportUDPConn struct {
	conn       *net.UDPConn
	remoteAddr *net.UDPAddr
	metadata   *common.Metadata
}

func (c *TransportUDPConn) Write(packet common.Packet) error {
	_, err := c.conn.WriteToUDP(packet.Data(), c.remoteAddr)
	if err != nil {
		return err
	}
	return nil
}

func (c *TransportUDPConn) Metadata() *common.Metadata {
	return c.metadata
}

func (c *TransportUDPConn) Read() (*TransportUDPPacket, error) {
	buf := make([]byte, common.DefaultUDPBufferSize)
	n, addr, err := c.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}
	ipversion := buf[0] >> 4
	return &TransportUDPPacket{
		data: buf[:n],
		metadata: &common.Metadata{
			IpVersion: common.IpVersionType(ipversion),
			SrcIP:     addr.IP,
			SrcPort:   uint16(addr.Port),
			DstIP:     c.remoteAddr.IP,
			DstPort:   uint16(c.remoteAddr.Port),
		},
	}, nil
}
