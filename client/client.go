package client

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/transport"
	tunPkg "github.com/jabberwocky238/gasoline/tun"
)

// TunOpener allows the platform (e.g. Android VpnService) to create TUN devices.
// When set, the client uses this instead of creating TUN directly via sing-tun.
type TunOpener interface {
	// OpenTun creates a TUN device and returns its file descriptor.
	OpenTun(name string, address string, mtu int32) (int32, error)
}

type Config struct {
	// Server endpoint to dial, e.g. "1.2.3.4:443"
	Endpoint string
	// VNetID is the virtual network this client belongs to
	VNetID [16]byte
	// SessionID is this client's unique session identifier
	SessionID [16]byte
	// TUNName is the name of the TUN device (default: gtun-XXXX)
	TUNName string
	// Dialer creates the transport connection (TCP/UDP/QUIC)
	// Auth and handshake are handled internally by the Dialer.
	Dialer transport.Dialer
}

type Client struct {
	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc

	cfg       *Config
	tun       *tunPkg.Tun
	conn      transport.Conn
	tunOpener TunOpener
}

// SetPlatformTunOpener sets a platform-specific TUN opener (e.g. Android VpnService).
// Must be called before Start().
func (c *Client) SetPlatformTunOpener(opener TunOpener) {
	c.tunOpener = opener
}

func New(cfg *Config) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
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
	log.Infof("Handshake OK: assigned IP %s, allowed %v", cfg.IPPrefix.String(), cfg.AllowedRanges)

	// 2. Create TUN with assigned IP using the network prefix length from AllowedRanges
	tunAddr := cfg.IPPrefix // e.g. 10.0.0.2/32
	for _, r := range cfg.AllowedRanges {
		if r.Contains(cfg.IPPrefix.Addr()) {
			tunAddr = netip.PrefixFrom(cfg.IPPrefix.Addr(), r.Bits()) // e.g. 10.0.0.2/24
			break
		}
	}

	var tun *tunPkg.Tun
	if c.tunOpener != nil {
		// Platform-provided TUN (e.g. Android VpnService)
		fd, err := c.tunOpener.OpenTun(c.cfg.TUNName, tunAddr.String(), int32(tunPkg.DefaultMTU))
		if err != nil {
			conn.Close()
			return fmt.Errorf("platform open TUN: %w", err)
		}
		tun, err = tunPkg.NewFromFD(int(fd))
		if err != nil {
			conn.Close()
			return fmt.Errorf("wrap TUN fd: %w", err)
		}
	} else {
		// Direct TUN creation (desktop: Windows/Linux/macOS)
		var err error
		tun, err = tunPkg.New(c.cfg.TUNName, tunAddr.String())
		if err != nil {
			conn.Close()
			return fmt.Errorf("create TUN: %w", err)
		}
		if err := tun.Start(); err != nil {
			conn.Close()
			return fmt.Errorf("start TUN: %w", err)
		}
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

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		buf := common.GetBuffer()
		n, err := c.tun.Read(*buf)
		if err != nil {
			common.PutBuffer(buf)
			log.Errorf("TUN read: %v", err)
			return
		}
		if n < 1 {
			common.PutBuffer(buf)
			continue
		}

		// Send packet to server
		if err := c.conn.WritePacket((*buf)[:n]); err != nil {
			common.PutBuffer(buf)
			log.Errorf("Conn write: %v", err)
			return
		}
		common.PutBuffer(buf)
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
