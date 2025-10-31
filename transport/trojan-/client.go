package trojan

import (
	"bytes"
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"wwww/transport/trojan/common"
	"wwww/transport/trojan/statistic"

	"github.com/sirupsen/logrus"
)

const (
	MaxPacketSize = 1024 * 8
)

const (
	Connect   Command = 1
	Associate Command = 3
	Mux       Command = 0x7f
)

type OutboundConn struct {
	// WARNING: do not change the order of these fields.
	// 64-bit fields that use `sync/atomic` package functions
	// must be 64-bit aligned on 32-bit systems.
	// Reference: https://github.com/golang/go/issues/599
	// Solution: https://github.com/golang/go/issues/11891#issuecomment-433623786
	sent uint64
	recv uint64

	metadata          *Metadata
	user              *statistic.User
	headerWrittenOnce sync.Once
	net.Conn
}

func (c *OutboundConn) Metadata() *Metadata {
	return c.metadata
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
		c.metadata.WriteTo(buf)
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
		return 0, common.NewError("trojan failed to flush header with payload").Base(err)
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
	logrus.Info("connection to", c.metadata, "closed", "sent:", HumanFriendlyTraffic(atomic.LoadUint64(&c.sent)), "recv:", HumanFriendlyTraffic(atomic.LoadUint64(&c.recv)))
	return c.Conn.Close()
}

type TrojanClient struct {
	underlay Client
	user     *statistic.User
	ctx      context.Context
	cancel   context.CancelFunc
}

func (c *TrojanClient) Close() error {
	c.cancel()
	return c.underlay.Close()
}

func (c *TrojanClient) DialConn(addr *Address, overlay Tunnel) (Conn, error) {
	conn, err := c.underlay.DialConn(addr, &Tunnel{})
	if err != nil {
		return nil, err
	}
	newConn := &OutboundConn{
		Conn: conn,
		user: c.user,
		metadata: &Metadata{
			Command: Connect,
			Address: addr,
		},
	}
	if _, ok := overlay.(*mux.Tunnel); ok {
		newConn.metadata.Command = Mux
	}

	go func(newConn *OutboundConn) {
		// if the trojan header is still buffered after 100 ms, the client may expect data from the server
		// so we flush the trojan header
		time.Sleep(time.Millisecond * 100)
		newConn.WriteHeader(nil)
	}(newConn)
	return newConn, nil
}

func (c *TrojanClient) DialPacket(Tunnel) (PacketConn, error) {
	fakeAddr := &Address{
		DomainName:  "UDP_CONN",
		AddressType: DomainName,
	}
	conn, err := c.underlay.DialConn(fakeAddr, &Tunnel{})
	if err != nil {
		return nil, err
	}
	return &_PacketConn{
		Conn: &OutboundConn{
			Conn: conn,
			user: c.user,
			metadata: &Metadata{
				Command: Associate,
				Address: fakeAddr,
			},
		},
	}, nil
}

func NewClient(ctx context.Context, client Client) (Client, error) {
	ctx, cancel := context.WithCancel(ctx)
	auth, err := statistic.NewAuthenticator(ctx, &statistic.Config{Passwords: []string{"password"}})
	if err != nil {
		cancel()
		return nil, err
	}

	var user *statistic.User
	for _, u := range auth.ListUsers() {
		user = u
		break
	}
	if user == nil {
		cancel()
		return nil, common.NewError("no valid user found")
	}

	logrus.Debug("trojan client created")
	return &TrojanClient{
		underlay: client,
		ctx:      ctx,
		user:     user,
		cancel:   cancel,
	}, nil
}
