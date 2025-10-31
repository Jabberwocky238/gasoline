package trojan

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"

	"github.com/sirupsen/logrus"
	"wwww/transport/trojan/common"
	"wwww/transport/trojan/statistic"
)

// InboundConn is a trojan inbound connection
type InboundConn struct {
	// WARNING: do not change the order of these fields.
	// 64-bit fields that use `sync/atomic` package functions
	// must be 64-bit aligned on 32-bit systems.
	// Reference: https://github.com/golang/go/issues/599
	// Solution: https://github.com/golang/go/issues/11891#issuecomment-433623786
	sent uint64
	recv uint64

	net.Conn
	auth     Authenticator
	user     User
	hash     string
	metadata *Metadata
	ip       string
}

func (c *InboundConn) Metadata() *Metadata {
	return c.metadata
}

func (c *InboundConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	atomic.AddUint64(&c.sent, uint64(n))
	c.user.AddTraffic(n, 0)
	return n, err
}

func (c *InboundConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	atomic.AddUint64(&c.recv, uint64(n))
	c.user.AddTraffic(0, n)
	return n, err
}

func (c *InboundConn) Close() error {
	logrus.Info("user", c.hash, "from", c.Conn.RemoteAddr(), "tunneling to", c.metadata.Address, "closed",
		"sent:", HumanFriendlyTraffic(atomic.LoadUint64(&c.sent)), "recv:", HumanFriendlyTraffic(atomic.LoadUint64(&c.recv)))
	c.user.DelIP(c.ip)
	return c.Conn.Close()
}

func (c *InboundConn) Auth() error {
	userHash := [56]byte{}
	n, err := c.Conn.Read(userHash[:])
	if err != nil || n != 56 {
		return common.NewError("failed to read hash").Base(err)
	}

	valid, user := c.auth.AuthUser(string(userHash[:]), c.Conn.RemoteAddr().String())
	if !valid {
		return common.NewError("invalid hash:" + string(userHash[:]))
	}
	c.hash = string(userHash[:])
	c.user = user

	ip, _, err := net.SplitHostPort(c.Conn.RemoteAddr().String())
	if err != nil {
		return common.NewError("failed to parse host:" + c.Conn.RemoteAddr().String()).Base(err)
	}
	c.ip = ip
	ok := user.AddIP(ip)
	if !ok {
		return common.NewError("ip limit reached")
	}

	crlf := [2]byte{}
	_, err = io.ReadFull(c.Conn, crlf[:])
	if err != nil {
		return err
	}

	c.metadata = &Metadata{}
	if err := c.metadata.ReadFrom(c.Conn); err != nil {
		return err
	}

	_, err = io.ReadFull(c.Conn, crlf[:])
	if err != nil {
		return err
	}
	return nil
}

// Server is a trojan tunnel server
type TrojanServer struct {
	auth       *statistic.Authenticator
	underlay   Server
	connChan   chan Conn
	muxChan    chan Conn
	packetChan chan PacketConn
	ctx        context.Context
	cancel     context.CancelFunc
}

func (s *TrojanServer) Close() error {
	s.cancel()
	return s.underlay.Close()
}

func (s *TrojanServer) acceptLoop() {
	for {
		conn, err := s.underlay.AcceptConn(&Tunnel{})
		if err != nil { // Closing
			logrus.Error(common.NewError("trojan failed to accept conn").Base(err))
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			continue
		}
		go func(conn Conn) {
			rewindConn := NewRewindConn(conn)
			rewindConn.SetBufferSize(128)
			defer rewindConn.StopBuffering()

			inboundConn := &InboundConn{
				Conn: rewindConn,
				auth: s.auth,
			}

			if err := inboundConn.Auth(); err != nil {
				rewindConn.Rewind()
				rewindConn.StopBuffering()
				logrus.Warn(common.NewError("connection with invalid trojan header from " + rewindConn.RemoteAddr().String()).Base(err))
				// s.redir.Redirect(&redirector.Redirection{
				// 	RedirectTo:  s.redirAddr,
				// 	InboundConn: rewindConn,
				// })
				return
			}

			rewindConn.StopBuffering()
			switch inboundConn.metadata.Command {
			case Connect:
				if inboundConn.metadata.DomainName == "MUX_CONN" {
					s.muxChan <- inboundConn
					logrus.Debug("mux(r) connection")
				} else {
					s.connChan <- inboundConn
					logrus.Debug("normal trojan connection")
				}

			case Associate:
				s.packetChan <- &_PacketConn{
					Conn: inboundConn,
				}
				logrus.Debug("trojan udp connection")
			case Mux:
				s.muxChan <- inboundConn
				logrus.Debug("mux connection")
			default:
				logrus.Error(common.NewError(fmt.Sprintf("unknown trojan command %d", inboundConn.metadata.Command)))
			}
		}(conn)
	}
}

func (s *TrojanServer) AcceptConn(nextTunnel Tunnel) (Conn, error) {
	switch nextTunnel.(type) {
	case *mux.Tunnel:
		select {
		case t := <-s.muxChan:
			return t, nil
		case <-s.ctx.Done():
			return nil, common.NewError("trojan client closed")
		}
	default:
		select {
		case t := <-s.connChan:
			return t, nil
		case <-s.ctx.Done():
			return nil, common.NewError("trojan client closed")
		}
	}
}

func (s *TrojanServer) AcceptPacket(Tunnel) (PacketConn, error) {
	select {
	case t := <-s.packetChan:
		return t, nil
	case <-s.ctx.Done():
		return nil, common.NewError("trojan client closed")
	}
}

func NewServer(ctx context.Context, cfg *Config, passwords []string) (Server, error) {
	ctx, cancel := context.WithCancel(ctx)

	auth, err := statistic.NewAuthenticator(ctx, &statistic.Config{Passwords: passwords})
	if err != nil {
		cancel()
		return nil, common.NewError("trojan failed to create authenticator")
	}

	s := &TrojanServer{
		underlay:   underlay,
		auth:       auth,
		connChan:   make(chan Conn, 32),
		muxChan:    make(chan Conn, 32),
		packetChan: make(chan PacketConn, 32),
		ctx:        ctx,
		cancel:     cancel,
	}

	go s.acceptLoop()
	logrus.Debug("trojan server created")
	return s, nil
}
