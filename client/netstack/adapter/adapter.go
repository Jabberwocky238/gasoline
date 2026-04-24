package adapter

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/jabberwocky238/gasoline/client/netstack"
)

// Config is the adapter's construction input. All fields are required
// except Mode/Socks5Peer (Mode defaults to ModeDirect).
type Config struct {
	// LocalIP is the client's overlay IP — this is both the source the stack
	// synthesizes on outbound NIC-OVERLAY packets and the self-exclusion
	// address for the pre-stack classifier.
	LocalIP netip.Addr

	// MTU of both gvisor NICs. Zero defaults to 1500.
	MTU uint32

	// OverlayRanges is consulted by the pre-stack classifier: any packet
	// read from the OS TUN whose destination falls in one of these prefixes
	// (and is not LocalIP) is shipped straight through ShipToOverlay without
	// being reassembled — keeping peer-to-peer TCP timing intact.
	OverlayRanges []netip.Prefix

	// Mode selects the public-destination policy. Defaults to ModeDirect
	// for the --experimental-fullhijack v1 feature flag; callers that want
	// SOCKS5 must set this explicitly and provide Socks5Peer.
	Mode netstack.Mode

	// Socks5Peer is the overlay address of a SOCKS5-exposing peer, used
	// only when Mode == ModeSocks5. Ignored otherwise.
	Socks5Peer netip.AddrPort

	// WriteToTUN delivers a raw IP packet back to local apps. Typically
	// `func(p []byte) error { _, e := tun.Write(p); return e }`.
	WriteToTUN func(ipPkt []byte) error

	// ShipToOverlay delivers a raw IP packet onto the overlay: caller wraps
	// it in an Ethernet frame, resolves the destination VMAC via ARP, and
	// writes to the overlay transport.Conn. Typically `vtap.Device.ShipIP`.
	ShipToOverlay func(ipPkt []byte) error

	// PhysicalDialer is the bypass dialer for non-overlay destinations.
	// MUST bind outbound sockets to the physical interface so they do not
	// loop back into the OS TUN. If nil, dialable flows (non-overlay) are
	// dropped.
	PhysicalDialer netstack.Dialer

	// SetupRoutes, if non-nil, is invoked exactly once during Start() —
	// after the stack's drain goroutines are up but before Start returns.
	// The integration point wires this to `tun.UpdateRouteOptions(...)`
	// to switch the OS TUN's route table to `0.0.0.0/0` (with whatever
	// excludes the caller wants) for full-hijack mode.
	//
	// Deliberately one-shot: no background watcher on interface changes.
	// If the physical default interface shifts at runtime, the operator
	// is expected to reconnect rather than have the adapter juggle routes.
	// A non-nil error aborts Start and the stack is torn down.
	SetupRoutes func() error
}

// Adapter owns a netstack.Stack configured with gasoline-shaped callbacks.
// Zero value is not usable; call New.
type Adapter struct {
	stack *netstack.Stack
	cfg   Config
}

// New constructs the Adapter and the underlying netstack.Stack, but does
// not start background goroutines. Call Start.
func New(cfg Config) (*Adapter, error) {
	if !cfg.LocalIP.IsValid() {
		return nil, errors.New("adapter: LocalIP required")
	}
	if cfg.WriteToTUN == nil {
		return nil, errors.New("adapter: WriteToTUN required")
	}
	if cfg.ShipToOverlay == nil {
		return nil, errors.New("adapter: ShipToOverlay required")
	}

	stackCfg := netstack.Config{
		LocalIP:         cfg.LocalIP,
		MTU:             cfg.MTU,
		OverlayRanges:   cfg.OverlayRanges,
		Mode:            cfg.Mode,
		Socks5Peer:      cfg.Socks5Peer,
		OnTunWrite:      cfg.WriteToTUN,
		OnOverlayWrite:  cfg.ShipToOverlay,
		OnOverlayBypass: cfg.ShipToOverlay,
		PhysicalDialer:  cfg.PhysicalDialer,
	}
	s, err := netstack.New(stackCfg)
	if err != nil {
		return nil, fmt.Errorf("adapter: %w", err)
	}
	return &Adapter{stack: s, cfg: cfg}, nil
}

// Start spawns the stack's drain goroutines and, if configured, calls the
// one-shot SetupRoutes hook. If SetupRoutes fails, the stack is closed
// before the error is returned so the caller doesn't have to clean up.
// Idempotent with respect to the stack; SetupRoutes itself fires at most
// once (the underlying sync.Once lives on netstack.Stack.Start).
func (a *Adapter) Start() error {
	if err := a.stack.Start(); err != nil {
		return err
	}
	if a.cfg.SetupRoutes != nil {
		if err := a.cfg.SetupRoutes(); err != nil {
			_ = a.stack.Close()
			return fmt.Errorf("adapter: SetupRoutes: %w", err)
		}
	}
	return nil
}

// Close tears the stack down. Idempotent.
func (a *Adapter) Close() error { return a.stack.Close() }

// OnTunPacket is the vtap-egress hook. It ALWAYS returns true: once the
// adapter is installed, every packet coming off the OS TUN is classified
// by netstack and dispatched either to the overlay (peer-to-peer bypass)
// or into the gvisor stack. vtap's original shipIP path is bypassed.
//
// The boolean return is still useful in the integration call site because
// it lets the caller toggle the adapter on/off: when the pointer is nil,
// this method is never invoked and vtap runs its original code path.
func (a *Adapter) OnTunPacket(ipPkt []byte) bool {
	a.stack.HandleTunInbound(ipPkt)
	return true
}

// OnOverlayPacket is the vtap-ingress hook. It consults the stack's flow
// table: if the packet belongs to a synthesized connection (e.g., SOCKS5
// upstream return traffic), it is injected into the stack and the method
// returns true so the caller skips tun.Write. Otherwise it returns false
// and the caller delivers the packet to the OS TUN as before.
//
// This is the mechanism that lets peer-to-peer transparent flows (which
// the stack never touched) coexist with stack-owned flows that happen to
// share destination IP/port ranges.
func (a *Adapter) OnOverlayPacket(ipPkt []byte) bool {
	return a.stack.MaybeHandleOverlayInbound(ipPkt)
}

// Stack exposes the underlying netstack for callers that want finer-grain
// access (metrics, future fakeip integration, etc.). Most users should
// stick to OnTunPacket / OnOverlayPacket.
func (a *Adapter) Stack() *netstack.Stack { return a.stack }
