package netstack

import "net/netip"

// routeDecision is the output of the pre-stack classifier for packets read
// from the OS TUN.
type routeDecision int

const (
	// decisionDrop: malformed or uninteresting (e.g. link-local multicast we
	// don't care about). Silently discard.
	decisionDrop routeDecision = iota
	// decisionOverlayBypass: dst is an overlay peer (≠ self). Ship raw via
	// OnOverlayBypass, do not enter gVisor. Keeps peer-to-peer TCP timing
	// and options intact.
	decisionOverlayBypass
	// decisionStack: inject into gVisor NIC-TUN. Apps' public-IP or non-overlay
	// private flows end up here and get reassembled for the handler.
	decisionStack
)

// dialDecision is the output of the post-stack classifier at flow-accept
// time (handler pulling ID off the ForwarderRequest).
type dialDecision int

const (
	dialDrop dialDecision = iota
	dialSocks5
	dialPhysical
)

// classifyInbound inspects the first byte of an IP packet to get the version,
// then the dst address, and returns a route decision. It never allocates.
func (s *Stack) classifyInbound(ipPkt []byte) (routeDecision, netip.Addr) {
	dst, ok := parseDstIP(ipPkt)
	if !ok {
		return decisionDrop, netip.Addr{}
	}
	// Self: e.g. local app loopback via TUN. Let gVisor handle (it'll RST
	// or echo depending on the transport).
	if dst == s.cfg.LocalIP {
		return decisionStack, dst
	}
	for _, p := range s.cfg.OverlayRanges {
		if p.Contains(dst) {
			return decisionOverlayBypass, dst
		}
	}
	return decisionStack, dst
}

// classifyDial is called when the stack has accepted a flow and we need to
// pick an upstream. dst is the original destination the app was trying to
// reach (ForwarderRequest.ID().LocalAddress).
//
// Policy:
//   - Private (non-overlay) ⇒ always physical. Mode has no effect here; an
//     overlay peer is already filtered out by the pre-stack bypass.
//   - Public + ModeSocks5  ⇒ dialSocks5. No fallback to physical: SOCKS5 was
//     explicitly chosen; if the peer is unreachable that's an operational
//     failure visible as a handshake error.
//   - Public + ModeDirect  ⇒ dialPhysical.
//   - Anything needing a dialer we don't have ⇒ dialDrop (forwarder RSTs).
func (s *Stack) classifyDial(dst netip.Addr) dialDecision {
	if isPrivate(dst) {
		if s.cfg.PhysicalDialer == nil {
			return dialDrop
		}
		return dialPhysical
	}
	// Public destination.
	if s.cfg.useSocks5() {
		return dialSocks5
	}
	if s.cfg.PhysicalDialer == nil {
		return dialDrop
	}
	return dialPhysical
}

// parseDstIP pulls the destination address out of a raw IPv4 or IPv6 packet.
// Returns false for short or unknown-version buffers.
func parseDstIP(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 1 {
		return netip.Addr{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}), true
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}, false
		}
		var a [16]byte
		copy(a[:], pkt[24:40])
		return netip.AddrFrom16(a), true
	}
	return netip.Addr{}, false
}

// isPrivate matches anything that is RFC-reserved as non-public: RFC1918,
// RFC6598 (CGN), loopback, link-local, RFC4193 (ULA), IPv6 loopback, IPv6
// link-local. "Private" here means "must not go out the public SOCKS5 path".
func isPrivate(a netip.Addr) bool {
	if !a.IsValid() {
		return true
	}
	if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsUnspecified() {
		return true
	}
	if a.Is4() {
		b := a.As4()
		switch {
		case b[0] == 10:
			return true
		case b[0] == 172 && b[1] >= 16 && b[1] <= 31:
			return true
		case b[0] == 192 && b[1] == 168:
			return true
		case b[0] == 100 && b[1] >= 64 && b[1] <= 127: // CGN
			return true
		}
		return false
	}
	// IPv6 ULA fc00::/7
	if a.Is6() {
		b := a.As16()
		if b[0]&0xfe == 0xfc {
			return true
		}
	}
	return false
}
