package udp

import (
	"context"
	"net"
	"sync"

	"github.com/jabberwocky238/gasoline/common"
)

type Listener struct {
	udpAddr *net.UDPAddr
	conn    *net.UDPConn
	handler func(conn common.Conn, metadata *common.Metadata)
}

func NewListener(ctx context.Context, addr string) (*Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	go func() {

	}()
	return &Listener{
		udpAddr: udpAddr,
		conn:    conn,
	}, nil
}

func (l *Listener) handshake() {
	// Perform any necessary handshake or authentication with the client
}
