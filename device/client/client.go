// Package client orchestrates the client-side handshake then keeps
// the transport alive. The legacy data plane (vtep + TUN bridge +
// SOCKS5) has been stripped — what remains is just:
//
//	dial -> handshake -> uplink rxLoop -> keepalive
//
// Frames received on the uplink are delivered to ClientConfig's
// frame callback (set externally) or dropped if none is provided.
package client

import (
	"crypto/tls"
	"fmt"
	"sync"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport"
	transportQuic "github.com/jabberwocky238/gasoline/transport/quic"
	transportTcp "github.com/jabberwocky238/gasoline/transport/tcp"
	transportUdp "github.com/jabberwocky238/gasoline/transport/udp"
	log "github.com/sirupsen/logrus"
)

// Client owns the lifecycle of one client-side session.
type Client struct {
	mu   sync.Mutex
	lctx *common.LogContext

	cfg    *ClientConfig
	dialer transport.Dialer

	// non-nil between Start and Close
	conn      transport.Conn
	uplink    *uplink
	keepalive *Keepalive
	onFrame   func([]byte)
}

// New constructs an unstarted Client.
func New(cfg *ClientConfig) (*Client, error) {
	clientAuth, err := auth.ParseClientAuth(cfg.AuthStr, []byte("default-fingerprint"))
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	preassigned := protocol.NewPreassignedSessionConfig(cfg.CID, cfg.VNI)
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

// SetFrameHandler installs a callback invoked for every inbound frame.
// Must be called before Start to take effect on the rxLoop. Safe to
// leave nil (frames get dropped).
func (c *Client) SetFrameHandler(fn func([]byte)) { c.onFrame = fn }

// Start dials, runs the handshake, and brings up the uplink + keepalive.
func (c *Client) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	conn, _, err := c.dialer.Dial(c.cfg.Endpoint)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	c.conn = conn
	c.lctx.Log().Infof("connected to %s", c.cfg.Endpoint)

	c.uplink = newUplink(c.lctx, conn, c.onFrame)
	c.keepalive = NewKeepalive(c.lctx, conn)

	c.uplink.Start()
	c.keepalive.Start()
	return nil
}

// Send writes one frame to the operator.
func (c *Client) Send(frame []byte) error {
	c.mu.Lock()
	u := c.uplink
	c.mu.Unlock()
	if u == nil {
		return fmt.Errorf("client: not started")
	}
	return u.SendFrame(frame)
}

// Close tears the data plane down and cancels the context.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keepalive != nil {
		c.keepalive.Stop()
		c.keepalive = nil
	}
	if c.uplink != nil {
		_ = c.uplink.Close()
		c.uplink = nil
	}
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
	c.lctx.Cancel()
	return nil
}

// --------------- transport factory ---------------

func createDialer(transportType string, cfg protocol.PreassignedSessionConfig, clientAuth auth.ClientAuthenticator) (transport.Dialer, error) {
	switch transportType {
	case "tcp":
		return transportTcp.NewDialer(cfg, clientAuth), nil
	case "udp":
		return transportUdp.NewDialer(cfg, clientAuth), nil
	case "quic":
		return transportQuic.NewDialer(cfg, clientAuth, &tls.Config{InsecureSkipVerify: true}), nil
	default:
		return nil, fmt.Errorf("unknown transport: %s", transportType)
	}
}
