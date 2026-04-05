package udp

import (
	"net"

	"github.com/jabberwocky238/gasoline/common"
)

type Dialer struct {
	endpoint string
	conn     *net.UDPConn
}

func NewDialer(endpoint string) *Dialer {
	return &Dialer{endpoint: endpoint}
}

func (d *Dialer) Dial() (common.Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", d.endpoint)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, err
	}
	d.conn = conn
	return d, nil
}

// common.PacketSender
func (d *Dialer) Write(packet Packet) error {

	_, err = d.conn.Write(packet.Data)
	if err != nil {
		return err
	}
	return nil
}
