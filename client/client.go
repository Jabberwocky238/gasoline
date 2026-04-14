package client

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	log "github.com/sirupsen/logrus"
	socks5 "github.com/things-go/go-socks5"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport"
	"github.com/jabberwocky238/gasoline/transport/quic"
	"github.com/jabberwocky238/gasoline/transport/tcp"
	"github.com/jabberwocky238/gasoline/transport/udp"
	tunPkg "github.com/jabberwocky238/gasoline/tun"
	singTun "github.com/sagernet/sing-tun"
)

// TunOpener allows the platform (e.g. Android VpnService) to create TUN devices.
type TunOpener interface {
	OpenTun(options singTun.Options) (int32, error)
}

type Client struct {
	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc

	cfg            *common.ClientConfig
	dialer         transport.Dialer
	tun            *tunPkg.Tun
	conn           transport.Conn
	tunOpener      TunOpener
	socks5Listener net.Listener
}

func (c *Client) SetPlatformTunOpener(opener TunOpener) {
	c.tunOpener = opener
}

func New(cfg *common.ClientConfig) (*Client, error) {
	clientAuth, err := auth.ParseClientAuth(cfg.AuthStr, []byte("default-fingerprint"))
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}

	var sessionID [16]byte
	dialer, err := createDialer(cfg.Transport, sessionID, cfg.VNetID, clientAuth)
	if err != nil {
		return nil, fmt.Errorf("dialer: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		cfg:    cfg,
		dialer: dialer,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

func (c *Client) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	conn, result, err := c.dialer.Dial(c.cfg.Endpoint)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	c.conn = conn

	hsCfg := &result.Config
	log.Infof("Handshake OK: assigned IP %s, allowed %v", hsCfg.IPPrefix.String(), hsCfg.AllowedRanges)

	tunAddr := hsCfg.IPPrefix
	for _, r := range hsCfg.AllowedRanges {
		if r.Contains(hsCfg.IPPrefix.Addr()) {
			tunAddr = netip.PrefixFrom(hsCfg.IPPrefix.Addr(), r.Bits())
			break
		}
	}

	var tun *tunPkg.Tun
	if c.tunOpener != nil {
		tunOptions := buildTunOptions(c.cfg.TUNName, tunAddr, hsCfg.AllowedRanges)
		fd, err := c.tunOpener.OpenTun(tunOptions)
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

	log.Infof("TUN interface up: %s", hsCfg.IPPrefix.String())

	go c.routineTUNToConn()
	go c.routineConnToTUN()

	if c.cfg.Socks5Port > 0 {
		if err := c.startSocks5(); err != nil {
			return fmt.Errorf("socks5: %w", err)
		}
	}

	return nil
}

func (c *Client) routineTUNToConn() {
	defer log.Debugf("Routine: TUN→Conn stopped")

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

		if err := c.conn.WritePacket((*buf)[:n]); err != nil {
			common.PutBuffer(buf)
			log.Errorf("Conn write: %v", err)
			return
		}
		common.PutBuffer(buf)
	}
}

func (c *Client) routineConnToTUN() {
	defer log.Debugf("Routine: Conn→TUN stopped")

	buf := common.GetBuffer()
	defer common.PutBuffer(buf)

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		n, err := c.conn.ReadPacket(*buf)
		if err != nil {
			log.Errorf("Conn read: %v", err)
			return
		}
		if n < 1 {
			continue
		}
		if _, err := c.tun.Write((*buf)[:n]); err != nil {
			log.Errorf("TUN write: %v", err)
			return
		}
	}
}

func (c *Client) Close() error {
	c.cancel()
	if c.socks5Listener != nil {
		c.socks5Listener.Close()
	}
	if c.conn != nil {
		c.conn.Close()
	}
	if c.tun != nil {
		c.tun.Close()
	}
	return nil
}

func (c *Client) startSocks5() error {
	addr := fmt.Sprintf("0.0.0.0:%d", c.cfg.Socks5Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	c.socks5Listener = ln

	server := socks5.NewServer()
	go func() {
		log.Infof("SOCKS5 proxy listening on %s", addr)
		if err := server.Serve(ln); err != nil {
			select {
			case <-c.ctx.Done():
			default:
				log.Errorf("SOCKS5 server error: %v", err)
			}
		}
	}()
	return nil
}

// --------------- Helpers ---------------

func createDialer(transportType string, sessionID [16]byte, vnetID [16]byte, clientAuth auth.ClientAuthenticator) (transport.Dialer, error) {
	switch transportType {
	case "tcp":
		return tcp.NewDialer(sessionID, vnetID, clientAuth), nil
	case "udp":
		return udp.NewDialer(sessionID, vnetID, clientAuth), nil
	case "quic":
		return quic.NewDialer(sessionID, vnetID, clientAuth, quic.InsecureClientTLS()), nil
	default:
		return nil, fmt.Errorf("unknown transport: %s", transportType)
	}
}

func buildTunOptions(name string, tunAddr netip.Prefix, allowedRanges []netip.Prefix) singTun.Options {
	var inet4Addr, inet6Addr []netip.Prefix
	var inet4Route, inet6Route []netip.Prefix

	if tunAddr.Addr().Is4() {
		inet4Addr = []netip.Prefix{tunAddr}
	} else {
		inet6Addr = []netip.Prefix{tunAddr}
	}
	for _, r := range allowedRanges {
		if r.Addr().Is4() {
			inet4Route = append(inet4Route, r)
		} else {
			inet6Route = append(inet6Route, r)
		}
	}
	if len(inet4Route) == 0 && tunAddr.Addr().Is4() {
		inet4Route = []netip.Prefix{tunAddr}
	}
	if len(inet6Route) == 0 && tunAddr.Addr().Is6() {
		inet6Route = []netip.Prefix{tunAddr}
	}

	return singTun.Options{
		Name:              name,
		Inet4Address:      inet4Addr,
		Inet6Address:      inet6Addr,
		MTU:               tunPkg.DefaultMTU,
		StrictRoute:       true,
		Inet4RouteAddress: inet4Route,
		Inet6RouteAddress: inet6Route,
	}
}
