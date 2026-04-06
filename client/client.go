package client

import (
	"context"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/jabberwocky238/gasoline/device"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/transport"
	tunPkg "github.com/jabberwocky238/gasoline/tun"
)

type Config struct {
	// Server endpoint to dial, e.g. "1.2.3.4:443"
	Endpoint string
	// Client identity
	ClientID [16]byte
	// Auth strategy for handshake
	Auth protocol.ClientAuthenticator
	// Dialer creates the transport connection (TCP/UDP/QUIC)
	Dialer transport.Dialer
}

type Client struct {
	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc

	cfg  *Config
	tun  *tunPkg.Tun
	conn transport.Conn

	pools *device.Pools
}

func New(cfg *Config) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
		pools:  device.NewPool(),
	}
}

// Start dials the server, performs handshake, creates TUN, and starts packet forwarding.
func (c *Client) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 1. Dial + handshake
	conn, result, err := c.cfg.Dialer.Dial(c.cfg.Endpoint)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	c.conn = conn

	cfg := &result.Config
	log.Infof("Handshake OK: assigned IP %s", cfg.IPPrefix.String())

	// 2. Create TUN with assigned IP
	tun, err := tunPkg.New("gasoline-tun", cfg.IPPrefix.String())
	if err != nil {
		conn.Close()
		return fmt.Errorf("create TUN: %w", err)
	}
	if err := tun.Start(); err != nil {
		conn.Close()
		return fmt.Errorf("start TUN: %w", err)
	}
	c.tun = tun

	log.Infof("TUN interface up: %s", cfg.IPPrefix.String())

	// 3. Start bidirectional packet forwarding
	go c.routineTUNToConn()
	go c.routineConnToTUN()

	return nil
}

// routineTUNToConn reads IP packets from TUN and sends them to the server.
func (c *Client) routineTUNToConn() {
	defer log.Debugf("Routine: TUN→Conn stopped")
	log.Debugf("Routine: TUN→Conn started")

	buf := make([]byte, device.MaxMtu)
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		n, err := c.tun.Read(buf)
		if err != nil {
			log.Errorf("TUN read: %v", err)
			return
		}
		if n < 1 {
			continue
		}

		// Send packet to server
		if err := c.conn.WritePacket(buf[:n]); err != nil {
			log.Errorf("Conn write: %v", err)
			return
		}
	}
}

// routineConnToTUN reads decrypted packets from the server and writes them to TUN.
func (c *Client) routineConnToTUN() {
	defer log.Debugf("Routine: Conn→TUN stopped")
	log.Debugf("Routine: Conn→TUN started")

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		data, err := c.conn.ReadPacket()
		if err != nil {
			log.Errorf("Conn read: %v", err)
			return
		}
		if len(data) == 0 {
			continue
		}

		if _, err := c.tun.Write(data); err != nil {
			log.Errorf("TUN write: %v", err)
			return
		}
	}
}

func (c *Client) Close() error {
	c.cancel()
	if c.conn != nil {
		c.conn.Close()
	}
	if c.tun != nil {
		c.tun.Close()
	}
	return nil
}

