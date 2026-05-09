// Package client orchestrates the client-side handshake then assembles
// the data plane out of three loosely-coupled components:
//
//		            +--------+  L3   +---------------+   L2   +--------+   AEAD
//		            |  TUN   |<----->|  vtep.Device  |<------>| uplink |<------> operator
//		            +--------+       +---------------+        +--------+
//		             ↑     ↑              ↑                       ↑
//		         tun.Bridge              ARP/FDB           keepalive intercept
//
//	  - tun.Bridge   : pumps IP packets between the OS TUN and vtep
//	                   (ingress = L3Sink, egress = goroutine).
//
//	  - vtep.Device  : userspace VTEP — ARP table, FDB-learning bridge,
//	                   BUM flooding. Knows nothing about transport.
//
//	  - uplink       : transport.Conn → vtep.Port adapter. SendFrame is
//	                   the egress; an rxLoop pumps the ingress. Keepalive
//	                   replies are filtered out before vtep sees them.
package client

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/jabberwocky238/gasoline/cmd/client/quicksocks5"
	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/device/tun"
	"github.com/jabberwocky238/gasoline/device/vtep"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport"
	"github.com/jabberwocky238/gasoline/transport/quic"
	"github.com/jabberwocky238/gasoline/transport/tcp"
	"github.com/jabberwocky238/gasoline/transport/udp"
	singTun "github.com/sagernet/sing-tun"
)

// TunOpener allows the platform (e.g. Android VpnService) to create TUN devices.
type TunOpener interface {
	OpenTun(options singTun.Options) (int32, error)
}

// Client owns the lifecycle of one client-side session.
type Client struct {
	mu  sync.Mutex
	ctx *common.GasolineGeneralContext

	cfg          *ClientConfig
	dialer       transport.Dialer
	tunOpener    TunOpener
	socks5Server *quicksocks5.Server

	// data-plane components — non-nil between Start and Close
	conn      transport.Conn
	tunDev    *tun.Tun
	vtepDev   *vtep.Device
	bridge    *tun.Bridge
	uplink    *uplink
	keepalive *Keepalive
}

func (c *Client) SetPlatformTunOpener(opener TunOpener) { c.tunOpener = opener }

func New(cfg *ClientConfig) (*Client, error) {
	clientAuth, err := auth.ParseClientAuth(cfg.AuthStr, []byte("default-fingerprint"))
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	dialer, err := createDialer(cfg.Transport, cfg.VMAC, cfg.VNI, clientAuth)
	if err != nil {
		return nil, fmt.Errorf("dialer: %w", err)
	}

	base := cfg.Logger
	if base == nil {
		base = log.StandardLogger()
	}
	entry := base.WithFields(log.Fields{
		"component": "client",
		"vni":       cfg.VNI.String(),
		"vmac":      vmacString(cfg.VMAC),
	})

	return &Client{
		cfg:    cfg,
		dialer: dialer,
		ctx:    common.NewGasolineCtx(context.Background(), entry),
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
	c.ctx.Logger().Infof("Handshake OK: assigned IP %s, allowed %v", hsCfg.IPPrefix, hsCfg.AllowedRanges)
	c.conn = conn

	ranges := make([]string, len(hsCfg.AllowedRanges))
	for i, r := range hsCfg.AllowedRanges {
		ranges[i] = r.String()
	}
	c.connInfo = &ConnInfo{
		IP:            hsCfg.IPPrefix.String(),
		VMAC:          vmacString(c.cfg.VMAC),
		AllowedRanges: ranges,
	}

	// 2. Open TUN device.
	tunAddr := pickTunAddr(hsCfg.IPPrefix, hsCfg.AllowedRanges)
	tunDev, err := c.openTun(tunAddr, hsCfg.AllowedRanges)
	if err != nil {
		conn.Close()
		return err
	}
	c.tunDev = tunDev
	c.ctx.Logger().Infof("TUN interface up: %s", hsCfg.IPPrefix)

	// 3. Build the VTEP — IP address comes straight from the handshake.
	c.vtepDev = vtep.New(c.ctx, c.cfg.VMAC, hsCfg.IPPrefix.Addr())

	// 4. Keepalive: random 10–15s ticker, src=selfMAC / dst=all-zero out,
	//    expects (dst=selfMAC, src=all-zero) back. The reply is intercepted
	//    in the uplink rxLoop and routed straight to NotifyReply, never
	//    reaching the VTEP.
	c.keepalive = NewKeepalive(c.ctx, conn, c.cfg.VMAC)

	// 5. Uplink — single vtep.Port wrapping the encrypted tunnel.
	c.uplink = newUplink(c.ctx, conn, c.vtepDev, c.cfg.VMAC, c.keepalive.NotifyReply)
	if err := c.vtepDev.AttachPort(c.uplink); err != nil {
		c.shutdown()
		return fmt.Errorf("vtep attach uplink: %w", err)
	}

	// 6. TUN bridge — egress goroutine + L3 sink registration.
	bridge, err := tun.NewBridge(c.ctx, tunDev, c.vtepDev)
	if err != nil {
		c.shutdown()
		return fmt.Errorf("tun bridge: %w", err)
	}
	c.bridge = bridge

	// 7. Spin everything up.
	c.uplink.Start()
	c.bridge.Start()
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
func (c *Client) ARP() *vtep.ARPTable {
	if c.vtepDev == nil {
		return nil
	}
	return c.vtepDev.ARP()
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.shutdown()
	c.ctx.Cancel()
	c.connInfo = nil
	return nil
}

// shutdown tears the data-plane components down in dependency order.
// Caller holds c.mu.
func (c *Client) shutdown() {
	if c.socks5Server != nil {
		c.socks5Server.Close()
		c.socks5Server = nil
	}
	if c.keepalive != nil {
		c.keepalive.Stop()
	}
	if c.bridge != nil {
		c.bridge.Close()
	}
	if c.uplink != nil {
		c.uplink.Close()
	}
	if c.vtepDev != nil {
		c.vtepDev.Close()
	}
	if c.tunDev != nil {
		c.tunDev.Close()
	}
	if c.conn != nil {
		c.conn.Close()
	}
}

func (c *Client) startSocks5() error {
	srv, err := quicksocks5.Start(c.ctx, c.cfg.Socks5Port, c.ctx.Logger())
	if err != nil {
		return err
	}
	c.socks5Server = srv
	return nil
}

// --------------- TUN open helpers ---------------

func (c *Client) openTun(addr netip.Prefix, allowed []netip.Prefix) (*tun.Tun, error) {
	if c.tunOpener != nil {
		opts := buildTunOptions(c.cfg.TUNName, addr, allowed)
		fd, err := c.tunOpener.OpenTun(opts)
		if err != nil {
			return nil, fmt.Errorf("platform open TUN: %w", err)
		}
		t, err := tun.NewFromFD(int(fd))
		if err != nil {
			return nil, fmt.Errorf("wrap TUN fd: %w", err)
		}
		return t, nil
	}
	t, err := tun.New(c.cfg.TUNName, addr.String())
	if err != nil {
		return nil, fmt.Errorf("create TUN: %w", err)
	}
	if err := t.Start(); err != nil {
		t.Close()
		return nil, fmt.Errorf("start TUN: %w", err)
	}
	return t, nil
}

// pickTunAddr widens the assigned /32 to the prefix length of whatever
// allowed-range covers it (mirrors the legacy behaviour).
func pickTunAddr(assigned netip.Prefix, allowed []netip.Prefix) netip.Prefix {
	for _, r := range allowed {
		if r.Contains(assigned.Addr()) {
			return netip.PrefixFrom(assigned.Addr(), r.Bits())
		}
	}
	return assigned
}

func vmacString(m common.VMAC) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

// --------------- transport / TUN factory boilerplate ---------------

func createDialer(transportType string, vni common.VNI, clientAuth auth.ClientAuthenticator) (transport.Dialer, error) {
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
		MTU:               tun.DEFAULT_MTU,
		StrictRoute:       true,
		Inet4RouteAddress: inet4Route,
		Inet6RouteAddress: inet6Route,
	}
}
