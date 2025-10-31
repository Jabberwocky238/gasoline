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
	return conn, nil
}
