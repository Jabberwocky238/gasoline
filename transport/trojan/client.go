package trojan

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"wwww/transport"
)

const (
	MaxPacketSize = 1024 * 8
)

type OutboundConn struct {
	// WARNING: do not change the order of these fields.
	// 64-bit fields that use `sync/atomic` package functions
	// must be 64-bit aligned on 32-bit systems.
	// Reference: https://github.com/golang/go/issues/599
	// Solution: https://github.com/golang/go/issues/11891#issuecomment-433623786
	sent uint64
	recv uint64

	user              *User
	headerWrittenOnce sync.Once
	net.Conn
}

func (c *OutboundConn) WriteHeader(payload []byte) (bool, error) {
	var err error
	written := false
	c.headerWrittenOnce.Do(func() {
		hash := c.user.Hash()
		buf := bytes.NewBuffer(make([]byte, 0, MaxPacketSize))
		crlf := []byte{0x0d, 0x0a}
		buf.Write([]byte(hash))
		buf.Write(crlf)
		if payload != nil {
			buf.Write(payload)
		}
		_, err = c.Conn.Write(buf.Bytes())
		if err == nil {
			written = true
		}
	})
	return written, err
}

func (c *OutboundConn) Write(p []byte) (int, error) {
	written, err := c.WriteHeader(p)
	if err != nil {
		return 0, fmt.Errorf("trojan failed to flush header with payload: %w", err)
	}
	if written {
		return len(p), nil
	}
	n, err := c.Conn.Write(p)
	c.user.AddTraffic(n, 0)
	atomic.AddUint64(&c.sent, uint64(n))
	return n, err
}

func (c *OutboundConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.user.AddTraffic(0, n)
	atomic.AddUint64(&c.recv, uint64(n))
	return n, err
}

func (c *OutboundConn) Close() error {
	return c.Conn.Close()
}

type TrojanClient struct {
	cfg      *ClientConfig
	underlay transport.TransportClient
	user     *User
	ctx      context.Context
	cancel   context.CancelFunc
}

func (c *TrojanClient) Close() error {
	c.cancel()
	return c.underlay.Close()
}

func (c *TrojanClient) Dial(addr string) (transport.TransportConn, error) {
	conn, err := c.underlay.Dial(addr)
	if err != nil {
		return nil, err
	}
	newConn := &OutboundConn{
		Conn: conn,
		user: c.user,
	}

	go func(newConn *OutboundConn) {
		// if the trojan header is still buffered after 100 ms, the client may expect data from the server
		// so we flush the trojan header
		time.Sleep(time.Millisecond * 100)
		newConn.WriteHeader(nil)
	}(newConn)
	return newConn, nil
}

func NewClient(ctx context.Context, client transport.TransportClient, cfg *ClientConfig) *TrojanClient {
	ctx, cancel := context.WithCancel(ctx)
	auth := NewAuthenticator(ctx, []string{cfg.Password})
	user, err := auth.GetUser(SHA224String(cfg.Password))
	if err != nil {
		panic(err)
	}
	return &TrojanClient{
		underlay: client,
		cfg:      cfg,
		ctx:      ctx,
		user:     user,
		cancel:   cancel,
	}
}
