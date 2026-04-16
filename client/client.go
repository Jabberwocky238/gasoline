package client

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	log "github.com/sirupsen/logrus"
	socks5 "github.com/things-go/go-socks5"

	tap "github.com/jabberwocky238/gasoline/client/vtap"
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

// Client orchestrates the handshake then hands off the data plane to a
// tap.Device that owns TUN ⇄ ARP/Eth ⇄ Conn for the lifetime of the session.
type Client struct {
	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc

	cfg            *common.ClientConfig
	dialer         transport.Dialer
	tunOpener      TunOpener
	socks5Listener net.Listener

	tun       *tunPkg.Tun
	dev       *tap.Device
	keepalive *Keepalive

	connInfo *ConnInfo // populated after successful handshake
}

// ConnInfo holds the connection details returned by the server handshake.
type ConnInfo struct {
	IP            string   `json:"ip"`
	VMAC          string   `json:"vmac"`
	AllowedRanges []string `json:"allowed_ranges"`
}

func (c *Client) SetPlatformTunOpener(opener TunOpener) {
	c.tunOpener = opener
}

func New(cfg *common.ClientConfig) (*Client, error) {
	clientAuth, err := auth.ParseClientAuth(cfg.AuthStr, []byte("default-fingerprint"))
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}

	dialer, err := createDialer(cfg.Transport, cfg.VMAC, cfg.VNI, clientAuth)
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

	// 1. Handshake (independent phase).
	conn, result, err := c.dialer.Dial(c.cfg.Endpoint)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	hsCfg := &result.Config
	log.Infof("Handshake OK: assigned IP %s, allowed %v", hsCfg.IPPrefix.String(), hsCfg.AllowedRanges)

	// Store connection info for the caller to retrieve via GetConnInfo().
	ranges := make([]string, len(hsCfg.AllowedRanges))
	for i, r := range hsCfg.AllowedRanges {
		ranges[i] = r.String()
	}
	c.connInfo = &ConnInfo{
		IP:            hsCfg.IPPrefix.String(),
		VMAC:          fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", c.cfg.VMAC[0], c.cfg.VMAC[1], c.cfg.VMAC[2], c.cfg.VMAC[3], c.cfg.VMAC[4], c.cfg.VMAC[5]),
		AllowedRanges: ranges,
	}

	// 2. Open TUN device.
	tunAddr := hsCfg.IPPrefix
	for _, r := range hsCfg.AllowedRanges {
		if r.Contains(hsCfg.IPPrefix.Addr()) {
			tunAddr = netip.PrefixFrom(hsCfg.IPPrefix.Addr(), r.Bits())
			break
		}
	}

	var tunDev *tunPkg.Tun
	if c.tunOpener != nil {
		tunOptions := buildTunOptions(c.cfg.TUNName, tunAddr, hsCfg.AllowedRanges)
		fd, err := c.tunOpener.OpenTun(tunOptions)
		if err != nil {
			conn.Close()
			return fmt.Errorf("platform open TUN: %w", err)
		}
		tunDev, err = tunPkg.NewFromFD(int(fd))
		if err != nil {
			conn.Close()
			return fmt.Errorf("wrap TUN fd: %w", err)
		}
	} else {
		tunDev, err = tunPkg.New(c.cfg.TUNName, tunAddr.String())
		if err != nil {
			conn.Close()
			return fmt.Errorf("create TUN: %w", err)
		}
		if err := tunDev.Start(); err != nil {
			conn.Close()
			return fmt.Errorf("start TUN: %w", err)
		}
	}
	c.tun = tunDev
	log.Infof("TUN interface up: %s", hsCfg.IPPrefix.String())

	// 3. Build the TAP device (TUN ⇄ Conn) and start its loops.
	c.dev = tap.New(tunDev, conn, c.cfg.VMAC, hsCfg.IPPrefix)

	// 4. Keepalive: random 10–15s ticker, src=selfMAC / dst=all-zero out,
	//    expects (dst=selfMAC, src=all-zero) back. Hook drops the reply
	//    before IP/ARP dispatch; Device routes it to NotifyReply.
	c.keepalive = NewKeepalive(conn, c.cfg.VMAC)
	c.dev.SetKeepaliveHook(c.keepalive.NotifyReply)

	c.dev.Start()
	c.keepalive.Start()

	if c.cfg.Socks5Port > 0 {
		if err := c.startSocks5(); err != nil {
			return fmt.Errorf("socks5: %w", err)
		}
	}

	return nil
}

// GetConnInfo returns handshake connection details, or nil if not connected.
func (c *Client) GetConnInfo() *ConnInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connInfo
}

// ARP exposes the device-local ARP table for tooling/seeding.
func (c *Client) ARP() *tap.ARPTable {
	if c.dev == nil {
		return nil
	}
	return c.dev.ARP()
}

func (c *Client) Close() error {
	c.cancel()
	c.connInfo = nil
	if c.keepalive != nil {
		c.keepalive.Stop()
	}
	if c.socks5Listener != nil {
		c.socks5Listener.Close()
	}
	if c.dev != nil {
		c.dev.Close()
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

func createDialer(transportType string, vmac common.VMAC, vni common.VNI, clientAuth auth.ClientAuthenticator) (transport.Dialer, error) {
	switch transportType {
	case "tcp":
		return tcp.NewDialer(vmac, vni, clientAuth), nil
	case "udp":
		return udp.NewDialer(vmac, vni, clientAuth), nil
	case "quic":
		return quic.NewDialer(vmac, vni, clientAuth, quic.InsecureClientTLS()), nil
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
		MTU:               common.TunMTU,
		StrictRoute:       true,
		Inet4RouteAddress: inet4Route,
		Inet6RouteAddress: inet6Route,
	}
}
