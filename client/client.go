package client

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/transport"
	tunPkg "github.com/jabberwocky238/gasoline/tun"
)

// TunOpener allows the platform (e.g. Android VpnService) to create TUN devices.
type TunOpener interface {
	OpenTun(name string, address string, mtu int32) (int32, error)
}

type Config struct {
	Endpoint  string
	VNetID    [16]byte
	SessionID [16]byte
	TUNName   string
	Dialer    transport.Dialer
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

func (c *Client) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	conn, result, err := c.cfg.Dialer.Dial(c.cfg.Endpoint)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	c.conn = conn

	cfg := &result.Config
	log.Infof("Handshake OK: assigned IP %s, allowed %v", cfg.IPPrefix.String(), cfg.AllowedRanges)

	tunAddr := cfg.IPPrefix
	for _, r := range cfg.AllowedRanges {
		if r.Contains(cfg.IPPrefix.Addr()) {
			tunAddr = netip.PrefixFrom(cfg.IPPrefix.Addr(), r.Bits())
			break
		}
	}

	var tun *tunPkg.Tun
	if c.tunOpener != nil {
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

	go c.routineTUNToConn()
	go c.routineConnToTUN()
	go c.routineKeepalive()

	return nil
}

// routineTUNToConn reads IP packets from TUN and sends them with a data prefix.
func (c *Client) routineTUNToConn() {
	defer log.Debugf("Routine: TUN→Conn stopped")

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		buf := common.GetBuffer()
		n, err := c.tun.Read((*buf)[1:]) // reserve buf[0] for type prefix
		if err != nil {
			common.PutBuffer(buf)
			log.Errorf("TUN read: %v", err)
			return
		}
		if n < 1 {
			common.PutBuffer(buf)
			continue
		}

		(*buf)[0] = common.PacketData
		if err := c.conn.WritePacket((*buf)[:1+n]); err != nil {
			common.PutBuffer(buf)
			log.Errorf("Conn write: %v", err)
			return
		}
		common.PutBuffer(buf)
	}
}

// routineConnToTUN reads packets from the server, strips the type prefix,
// and writes IP packets to TUN.
func (c *Client) routineConnToTUN() {
	defer log.Debugf("Routine: Conn→TUN stopped")

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
		if len(data) < 1 {
			continue
		}

		switch data[0] {
		case common.PacketData:
			if len(data) < 2 {
				continue
			}
			if _, err := c.tun.Write(data[1:]); err != nil {
				log.Errorf("TUN write: %v", err)
				return
			}
		case common.PacketKeepalive:
			// Server echoed keepalive — nothing to do
		}
	}
}

// routineKeepalive sends periodic heartbeats to keep the session alive on the operator.
func (c *Client) routineKeepalive() {
	ticker := time.NewTicker(time.Duration(common.KeepaliveInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
		}

		if err := c.conn.WritePacket([]byte{common.PacketKeepalive}); err != nil {
			log.Errorf("Keepalive send failed: %v", err)
			return
		}
		log.Debugf("Keepalive sent")
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
