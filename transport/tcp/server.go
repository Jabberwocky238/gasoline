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

	connChan chan net.Conn
	ctx      context.Context
	cancel   context.CancelFunc
}

func NewTCPServer() *TCPServer {
	return &TCPServer{
		connChan: make(chan net.Conn, 1024),
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
		return conn, nil
	case <-t.ctx.Done():
		return nil, errors.New("server closed")
	}
}

func (t *TCPServer) Close() error {
	t.cancel()
	return t.listener.Close()
}
