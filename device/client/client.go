// Package client orchestrates the client-side handshake then keeps
// the transport alive:
//
//	dial -> handshake -> rxLoop -> keepalive
//
// When a TUN device is configured, inbound IP packets are written to
// it and outbound packets are read from it back into the transport.
// Without a TUN the rxLoop just drops everything (the transport stays
// alive thanks to keepalive, which is enough for some uses).
package client

import (
	"crypto/tls"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/device/client/quicksocks5"
	"github.com/jabberwocky238/gasoline/device/tun"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport"
	transportQuic "github.com/jabberwocky238/gasoline/transport/quic"
	_ "github.com/jabberwocky238/gasoline/transport/tcp" // self-registers
	_ "github.com/jabberwocky238/gasoline/transport/tls" // self-registers
	_ "github.com/jabberwocky238/gasoline/transport/udp" // self-registers
	log "github.com/sirupsen/logrus"
)

// Client owns the lifecycle of one client-side session.
type Client struct {
	mu   sync.Mutex
	lctx *common.LogContext

	cfg    *StaticClientConfig
	dialer transport.Dialer

	// non-nil between Start and Close
	sessionCtx *protocol.SessionContext
	conn       transport.Conn
	keepalive  *Keepalive
	tun        *tun.Tun
	socks5     *quicksocks5.Server

	closed atomic.Bool
}

// New constructs an unstarted Client.
func New(cfg *StaticClientConfig) (*Client, error) {
	clientAuth, err := auth.ParseClientAuth(cfg.AuthStr, []byte("default-fingerprint"))
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	preset := protocol.NewPresetSessionConfig(cfg.CID, cfg.VNI)

	var tlsConf *tls.Config
	switch cfg.Transport {
	case "tls", "quic":
		// QUIC requires ALPN; the helper sets it to match the server.
		tlsConf = transportQuic.InsecureClientTLS()
	}
	dialer, err := transport.NewDialer(cfg.Transport, preset, clientAuth, tlsConf)
	if err != nil {
		return nil, fmt.Errorf("dialer: %w", err)
	}

	logger := cfg.Logger
	if logger == nil {
		logger = log.StandardLogger()
	}
	lctx := common.NewLogContext(nil, logger).
		WithField("component", "client").
		WithField("vni", cfg.VNI).
		WithField("cid", cfg.CID)

	return &Client{
		cfg:    cfg,
		dialer: dialer,
		lctx:   lctx,
	}, nil
}

func (c *Client) SessionContext() protocol.SessionContext {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessionCtx.Copy()
}

// SetTun installs a TUN before Start. If the cfg.TUNName branch in
// Start sees c.tun already set, it skips the real-TUN allocation, so
// SetTun is the swap point for in-process fakes — pass a *tun.Tun
// built from tun.NewFromSingTun(yourMock) to plug an in-memory shim
// into the production data-plane lifecycle.
func (c *Client) SetTun(t *tun.Tun) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tun = t
}

// Dial performs the network connect + handshake and stores the
// resulting transport.Conn + *SessionContext on the Client. Returns
// a snapshot copy of the SessionContext so callers can inspect the
// assigned IP / prefix / etc. before calling Start.
//
// Idempotent: a second call after a successful first one is a no-op
// and returns the existing session.
func (c *Client) Dial() (protocol.SessionContext, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dialLocked()
}

// dialLocked is the shared implementation. Caller holds c.mu.
func (c *Client) dialLocked() (protocol.SessionContext, error) {
	if c.conn != nil && c.sessionCtx != nil {
		return c.sessionCtx.Copy(), nil
	}
	conn, sc, err := c.dialer.Dial(c.cfg.Endpoint)
	if err != nil {
		return protocol.SessionContext{}, fmt.Errorf("dial: %w", err)
	}
	c.conn = conn
	c.sessionCtx = sc
	c.lctx.Log().Infof("connected to %s; assigned %s in %s",
		c.cfg.Endpoint, sc.IP, sc.IPRanges)
	return sc.Copy(), nil
}

// Start brings up the data plane on top of an already-dialed (or
// not-yet-dialed) connection: TUN (if configured), keepalive, rx /
// tx pumps, and the optional SOCKS5 proxy. If Dial wasn't called
// first, Start dials itself.
func (c *Client) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, err := c.dialLocked(); err != nil {
		return err
	}
	sc := c.sessionCtx
	conn := c.conn

	hostPfx := netip.PrefixFrom(sc.IP, sc.IPRanges.Bits())

	// Optional TUN integration: open the kernel TUN at the
	// handshake-assigned address, write inbound IP packets to it, and
	// read outbound IP packets back into the transport.
	if c.cfg.TUNName != "" && c.tun == nil {
		if !sc.IP.IsValid() {
			c.shutdownLocked()
			return fmt.Errorf("tun: server returned no IP; cannot configure %q", c.cfg.TUNName)
		}
		t, err := tun.New(c.cfg.TUNName, hostPfx.String())
		if err != nil {
			c.shutdownLocked()
			return fmt.Errorf("tun open %q: %w", c.cfg.TUNName, err)
		}
		if err := t.Start(); err != nil {
			_ = t.Close()
			c.shutdownLocked()
			return fmt.Errorf("tun start: %w", err)
		}
		c.tun = t
		c.lctx.Log().Infof("tun %s up at %s", c.cfg.TUNName, hostPfx)
	}

	c.keepalive = NewKeepalive(c.lctx, conn)
	c.keepalive.Start()

	go c.rxLoop()
	if c.tun != nil {
		go c.tunReadLoop()
	}

	// Optional local SOCKS5 proxy for app-level traffic redirection
	// without OS-level routing changes.
	if c.cfg.Socks5Port > 0 {
		srv, err := quicksocks5.Start(c.lctx.Context(), c.cfg.Socks5Port, c.lctx.Log())
		if err != nil {
			c.lctx.Log().Errorf("socks5 start: %v", err)
			c.shutdownLocked()
			return fmt.Errorf("socks5 start: %w", err)
		}
		c.socks5 = srv
		c.lctx.Log().Infof("socks5 proxy listening on :%d", c.cfg.Socks5Port)
	}
	return nil
}

// Close tears the data plane down and cancels the context.
func (c *Client) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.shutdownLocked()
	c.lctx.Cancel()
	return nil
}

// shutdownLocked tears every resource down. Caller holds c.mu.
func (c *Client) shutdownLocked() {
	if c.socks5 != nil {
		_ = c.socks5.Close()
		c.socks5 = nil
	}
	if c.keepalive != nil {
		c.keepalive.Stop()
		c.keepalive = nil
	}
	if c.tun != nil {
		_ = c.tun.Close()
		c.tun = nil
	}
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}

// rxLoop reads frames from the transport. Inbound IP packets go to the
// TUN if configured; v3 keepalive replies and everything else are
// dropped (we don't echo back, otherwise we'd ping-pong with operator).
func (c *Client) rxLoop() {
	logger := c.lctx.Log()
	bufp := common.GetBuffer()
	defer common.PutBuffer(bufp)
	buf := *bufp
	for {
		select {
		case <-c.lctx.Done():
			return
		default:
		}
		n, err := c.conn.ReadPacket(buf)
		if err != nil {
			if c.closed.Load() {
				return
			}
			logger.Debugf("conn read: %v", err)
			return
		}
		if n == 0 {
			continue
		}
		// Drop the operator's keepalive reply (IP version 3).
		if buf[0]>>4 == 3 {
			continue
		}
		if c.tun == nil {
			continue
		}
		if _, err := c.tun.Write(buf[:n]); err != nil {
			logger.Debugf("tun write: %v", err)
		}
	}
}

// tunReadLoop pumps IP packets from the OS TUN into the transport.
func (c *Client) tunReadLoop() {
	logger := c.lctx.Log()
	buf := make([]byte, 65536)
	for {
		select {
		case <-c.lctx.Done():
			return
		default:
		}
		n, err := c.tun.Read(buf)
		if err != nil {
			if c.closed.Load() {
				return
			}
			logger.Debugf("tun read: %v", err)
			return
		}
		if n == 0 {
			continue
		}
		if err := c.conn.WritePacket(buf[:n]); err != nil {
			logger.Debugf("conn write: %v", err)
		}
	}
}
