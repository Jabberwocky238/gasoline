package netstack

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// Dialer is the interface the caller supplies for non-stack egress (physical
// NIC bypass). Implementations typically wrap a net.Dialer bound to a specific
// interface via Control hooks (SO_BINDTODEVICE / IP_BOUND_IF / interface index).
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error)
}

// Mode is the public-destination egress policy. It is an *explicit* choice
// made by the caller — there is no runtime fallback between modes. A flow
// that can't traverse the chosen mode (e.g. ModeSocks5 with an unreachable
// peer) is an operational failure, not a prompt to silently take the other
// path.
//
// Private destinations are unaffected by Mode: overlay peers go through the
// pre-stack bypass, non-overlay private goes through the physical dialer
// regardless of Mode.
type Mode int

const (
	// ModeDirect sends every public-destination flow through PhysicalDialer.
	// Socks5Peer, if set, is ignored. Chosen as the zero value because it
	// has no additional config requirements.
	ModeDirect Mode = iota
	// ModeSocks5 sends every public-destination flow through the SOCKS5
	// upstream on the overlay. Requires Socks5Peer to be set.
	ModeSocks5
)

func (m Mode) String() string {
	switch m {
	case ModeDirect:
		return "direct"
	case ModeSocks5:
		return "socks5"
	default:
		return "unknown"
	}
}

// Config is immutable after New. Everything the stack needs to decide routes
// and generate egress traffic is bundled here.
type Config struct {
	// LocalIP is this client's overlay IP. Used as the source address for
	// every packet the stack synthesizes onto NIC-OVERLAY (notably the SYN
	// of the SOCKS5 upstream connection) and as the self-IP exclusion in the
	// pre-stack classifier.
	LocalIP netip.Addr

	// MTU advertised by both NICs. If zero, defaults to 1500.
	MTU uint32

	// OverlayRanges is consulted by the pre-stack classifier. A packet whose
	// destination IP falls inside any of these prefixes AND is not LocalIP is
	// handed to OnOverlayBypass without entering gVisor.
	OverlayRanges []netip.Prefix

	// Mode picks the public-destination egress policy. See Mode docs.
	Mode Mode

	// Socks5Peer is the overlay address of a peer exposing a SOCKS5 server
	// (e.g. via `--quick-socks5` on the peer side). Required when
	// Mode == ModeSocks5; ignored otherwise.
	Socks5Peer netip.AddrPort

	// OnTunWrite receives every IP packet the stack wants to deliver back to
	// apps (SYN-ACK, ACKs, server-to-client data). The caller is expected to
	// write the bytes to the OS TUN device verbatim.
	OnTunWrite func(ipPkt []byte) error

	// OnOverlayWrite receives every IP packet the stack generated on
	// NIC-OVERLAY (the synthesized SOCKS5 upstream). The caller must wrap
	// each one in an Ethernet frame (dst MAC = Socks5Peer's VMAC, resolved
	// via ARP) and ship it over the overlay transport.
	OnOverlayWrite func(ipPkt []byte) error

	// OnOverlayBypass receives an IP packet the pre-stack classifier deemed
	// transparent overlay traffic (peer ⇄ peer). Identical shipping
	// requirements as OnOverlayWrite: wrap Ethernet + ARP + transport write.
	OnOverlayBypass func(ipPkt []byte) error

	// PhysicalDialer is used for the "go out the physical NIC" branch:
	//   - non-overlay private destinations (any Mode)
	//   - public destinations when Mode == ModeDirect
	// The caller is responsible for ensuring the dialer does NOT loop back
	// into the OS TUN (bind to the physical interface or add route exclusion
	// for the target IP). If nil, flows that would require it are dropped.
	PhysicalDialer Dialer

	// UDPIdleTimeout is the idle timeout for a single UDP flow. A flow is
	// torn down if neither direction sees a packet for this long. If zero,
	// defaults to 60s. Setting this too low will break protocols with long
	// idle periods (DTLS keepalives, some IoT heartbeats); too high holds
	// per-flow resources (upstream PacketConn, gvisor endpoint) past their
	// useful life.
	UDPIdleTimeout time.Duration

	// UDPWriteTimeout caps how long a UDP send may block on either the
	// upstream or downstream side. If zero, defaults to 5s. This exists so
	// a wedged receiver can't stall a proxy goroutine indefinitely.
	UDPWriteTimeout time.Duration
}

// useSocks5 is the sole gate for public-destination flows. Returns true iff
// the operator explicitly chose ModeSocks5 *and* the peer is configured; the
// latter is enforced at New(), so this is normally just a Mode check.
func (c *Config) useSocks5() bool {
	return c.Mode == ModeSocks5 && c.Socks5Peer.IsValid()
}

func (c *Config) mtu() uint32 {
	if c.MTU == 0 {
		return 1500
	}
	return c.MTU
}

func (c *Config) udpIdleTimeout() time.Duration {
	if c.UDPIdleTimeout == 0 {
		return 60 * time.Second
	}
	return c.UDPIdleTimeout
}

func (c *Config) udpWriteTimeout() time.Duration {
	if c.UDPWriteTimeout == 0 {
		return 5 * time.Second
	}
	return c.UDPWriteTimeout
}
