package trojan

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"wwww/transport"
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
	auth *Authenticator
	user *User
	hash string
	ip   string
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
	c.user.DelIP(c.ip)
	return c.Conn.Close()
}

func (c *InboundConn) Auth() error {
	userHash := [56]byte{}
	n, err := c.Conn.Read(userHash[:])
	if err != nil || n != 56 {
		return fmt.Errorf("failed to read hash: %w", err)
	}

	valid, user := c.auth.AuthUser(string(userHash[:]), c.Conn.RemoteAddr().String())
	if !valid {
		return fmt.Errorf("invalid hash: %s", string(userHash[:]))
	}
	c.hash = string(userHash[:])
	c.user = user

	ip, _, err := net.SplitHostPort(c.Conn.RemoteAddr().String())
	if err != nil {
		return fmt.Errorf("failed to parse host: %w", err)
	}
	c.ip = ip
	ok := user.AddIP(ip)
	if !ok {
		return fmt.Errorf("ip limit reached")
	}

	crlf := [2]byte{}

	_, err = io.ReadFull(c.Conn, crlf[:])
	if err != nil {
		return err
	}
	return nil
}

// Server is a trojan tunnel server
type TrojanServer struct {
	auth      *Authenticator
	underlay  transport.TransportServer
	connChan  chan transport.TransportConn
	ctx       context.Context
	cancel    context.CancelFunc
	redir     *Redirector
	redirAddr net.Addr
}

func (s *TrojanServer) Close() error {
	s.cancel()
	return s.underlay.Close()
}

func (s *TrojanServer) acceptLoop() {
	for conn := range s.underlay.Accept() {
		go func(conn transport.TransportConn) {
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
				fmt.Println("connection with invalid trojan header from", rewindConn.RemoteAddr().String(), "error:", err)
				s.redir.Redirect(&Redirection{
					RedirectTo:  s.redirAddr,
					InboundConn: rewindConn,
				})
				return
			}

			rewindConn.StopBuffering()
			s.connChan <- inboundConn
		}(conn)
	}
}

func (s *TrojanServer) Accept() <-chan transport.TransportConn {
	return s.connChan
}

func (s *TrojanServer) Listen(host string, port int) error {
	go s.acceptLoop()
	return s.underlay.Listen(host, port)
}

func NewServer(ctx context.Context, underlay transport.TransportServer, cfg *ServerConfig) transport.TransportServer {
	auth := NewAuthenticator(ctx, cfg.Passwords)
	ctx, cancel := context.WithCancel(ctx)

	if cfg.RedirectHost == "" {
		cfg.RedirectHost = "127.0.0.1"
	}
	redirAddrNet := net.ParseIP(cfg.RedirectHost)
	redirAddrAddr := &net.TCPAddr{
		IP:   redirAddrNet,
		Port: cfg.RedirectPort,
	}
	s := &TrojanServer{
		underlay:  underlay,
		auth:      auth,
		redirAddr: redirAddrAddr,
		connChan:  make(chan transport.TransportConn, 32),
		ctx:       ctx,
		cancel:    cancel,
		redir:     NewRedirector(ctx),
	}

	fmt.Println("trojan server created")
	return s
}
