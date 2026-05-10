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
	"sync"
	"sync/atomic"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/device/tun"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport"
	transportQuic "github.com/jabberwocky238/gasoline/transport/quic"
	transportTcp "github.com/jabberwocky238/gasoline/transport/tcp"
	transportTls "github.com/jabberwocky238/gasoline/transport/tls"
	transportUdp "github.com/jabberwocky238/gasoline/transport/udp"
	log "github.com/sirupsen/logrus"
)

// Client owns the lifecycle of one client-side session.
type Client struct {
	mu   sync.Mutex
	lctx *common.LogContext

	cfg    *StaticClientConfig
	dialer transport.Dialer

	// non-nil between Start and Close
	conn      transport.Conn
	keepalive *Keepalive
	tun       *tun.Tun

	closed atomic.Bool
}

// New constructs an unstarted Client.
func New(cfg *StaticClientConfig) (*Client, error) {
	clientAuth, err := auth.ParseClientAuth(cfg.AuthStr, []byte("default-fingerprint"))
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	preassigned := protocol.NewPresetSessionConfig(cfg.CID, cfg.VNI)
	dialer, err := createDialer(cfg.Transport, preassigned, clientAuth)
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
		WithField("cid", fmt.Sprintf("%x", cfg.CID))

	return &Client{
		cfg:    cfg,
		dialer: dialer,
		lctx:   lctx,
	}, nil
}

// Start dials, runs the handshake, and brings up the data plane.
func (c *Client) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	conn, result, err := c.dialer.Dial(c.cfg.Endpoint)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	c.conn = conn
	c.lctx.Log().Infof("connected to %s; assigned prefix %s", c.cfg.Endpoint, result.Prefix)

	// Optional TUN integration: when TUNName is set we open the kernel
	// TUN at the handshake-assigned prefix, write inbound IP packets to
	// it, and read outbound IP packets back into the transport.
	if c.cfg.TUNName != "" {
		if !result.Prefix.IsValid() {
			_ = conn.Close()
			return fmt.Errorf("tun: server returned no prefix; cannot configure %q", c.cfg.TUNName)
		}
		t, err := tun.New(c.cfg.TUNName, result.Prefix.String())
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("tun open %q: %w", c.cfg.TUNName, err)
		}
		if err := t.Start(); err != nil {
			_ = t.Close()
			_ = conn.Close()
			return fmt.Errorf("tun start: %w", err)
		}
		c.tun = t
		c.lctx.Log().Infof("tun %s up at %s", c.cfg.TUNName, result.Prefix)
	}

	c.keepalive = NewKeepalive(c.lctx, conn)
	c.keepalive.Start()

	go c.rxLoop()
	if c.tun != nil {
		go c.tunReadLoop()
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
	c.lctx.Cancel()
	return nil
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

// --------------- transport factory ---------------

func createDialer(transportType string, cfg protocol.PresetSessionConfig, clientAuth auth.ClientAuthenticator) (transport.Dialer, error) {
	switch transportType {
	case "tcp":
		return transportTcp.NewDialer(cfg, clientAuth), nil
	case "udp":
		return transportUdp.NewDialer(cfg, clientAuth), nil
	case "quic":
		return transportQuic.NewDialer(cfg, clientAuth, &tls.Config{InsecureSkipVerify: true}), nil
	case "tls":
		return transportTls.NewDialer(cfg, clientAuth, &tls.Config{InsecureSkipVerify: true}), nil
	default:
		return nil, fmt.Errorf("unknown transport: %s", transportType)
	}
}
