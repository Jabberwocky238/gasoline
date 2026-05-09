package operator

import (
	"crypto/sha256"
	"fmt"
	"net/netip"

	"github.com/jabberwocky238/gasoline/common"
)

// v4State is the guarded mutable state for an IPv4 pool. Nil on IPv6 pools.
type v4State struct {
	next    uint32          // next sequence to try
	freed   []uint32        // recycled sequences
	inUse   map[uint32]bool // all known in-use sequences (local + remote)
	maxHost uint32          // max usable host count
}

// VNetPool manages IP allocation for a single VNet.
//
// IPv4: sequential pool with recycle list (state-tracking, guarded).
// IPv6: deterministic derivation from (SessionID, VNI) — no state required.
//
//	ReserveIP / UnreserveIP / ReleaseIP are no-ops on v6 pools since
//	there is no shared allocation table to coordinate.
type VNetPool struct {
	VNI      common.VNI
	Prefix   netip.Prefix
	baseAddr netip.Addr

	// v4 is nil for IPv6 pools.
	v4 *common.MutexGuard[v4State]
}

// IsV4 reports whether this pool allocates IPv4 addresses.
func (p *VNetPool) IsV4() bool { return p.Prefix.Addr().Is4() }

// AllocateIP returns an IP for the given session.
// For IPv4 pools, the sessionID is ignored (sequential allocation).
// For IPv6 pools, the IP is deterministically derived from (sessionID, VNI).
func (p *VNetPool) AllocateIP(sessionID [16]byte) (netip.Addr, error) {
	if !p.IsV4() {
		return p.deriveV6(sessionID), nil
	}
	return p.allocateV4()
}

func (p *VNetPool) allocateV4() (netip.Addr, error) {
	var (
		out netip.Addr
		err error
	)
	p.v4.Write(func(s *v4State) {
		// Try freed list first
		for len(s.freed) > 0 {
			seq := s.freed[len(s.freed)-1]
			s.freed = s.freed[:len(s.freed)-1]
			if !s.inUse[seq] {
				out = addToAddrV4(p.baseAddr, seq)
				s.inUse[seq] = true
				return
			}
		}

		// Scan from s.next, wrapping around once
		start := s.next
		wrapped := false
		for {
			seq := s.next
			s.next++
			if s.next > s.maxHost {
				s.next = 2 // wrap around
			}

			if !wrapped && s.next == start {
				err = fmt.Errorf("IP pool exhausted for vni %s", p.VNI)
				return
			}
			if s.next == start {
				wrapped = true
			}

			if s.inUse[seq] {
				continue
			}

			ip := addToAddrV4(p.baseAddr, seq)
			if !p.Prefix.Contains(ip) {
				continue
			}

			s.inUse[seq] = true
			out = ip
			return
		}
	})
	return out, err
}

// deriveV6 computes a stateless IPv6 address for a session:
//
//	host bits = sha256(SessionID || VNI[3bytes])[: hostBits/8]
//	result    = prefix | host bits
//
// Because the host-bit space is sparse (≥ 64 bits for typical /64 prefixes),
// collision probability across ~10^9 concurrent sessions is negligible.
func (p *VNetPool) deriveV6(sessionID [16]byte) netip.Addr {
	base := p.baseAddr.As16()
	bits := p.Prefix.Bits()

	// Hash input = sessionID (16B) + VNI (3B big-endian)
	h := sha256.New()
	h.Write(sessionID[:])
	vb := p.VNI.Bytes3()
	h.Write(vb[:])
	sum := h.Sum(nil)

	networkBytes := bits / 8
	remainder := bits % 8

	if networkBytes < 16 {
		if remainder != 0 {
			mask := byte(0xFF << (8 - remainder))
			base[networkBytes] = (base[networkBytes] & mask) | (sum[networkBytes] &^ mask)
			networkBytes++
		}
		for i := networkBytes; i < 16; i++ {
			base[i] = sum[i-(bits/8)]
		}
	}
	return netip.AddrFrom16(base)
}

// ReleaseIP returns an IPv4 address back to the pool. No-op for IPv6.
func (p *VNetPool) ReleaseIP(ip netip.Addr) {
	if !ip.Is4() || p.v4 == nil {
		return
	}
	seq := p.ipToSeqV4(ip)
	p.v4.Write(func(s *v4State) {
		if !s.inUse[seq] {
			return
		}
		delete(s.inUse, seq)
		s.freed = append(s.freed, seq)
	})
}

// ReserveIP marks an IPv4 address as in-use. No-op for IPv6 (stateless).
func (p *VNetPool) ReserveIP(ip netip.Addr) {
	if !ip.Is4() || p.v4 == nil {
		return
	}
	seq := p.ipToSeqV4(ip)
	p.v4.Write(func(s *v4State) { s.inUse[seq] = true })
}

// UnreserveIP removes an IPv4 reservation. No-op for IPv6.
func (p *VNetPool) UnreserveIP(ip netip.Addr) {
	if !ip.Is4() || p.v4 == nil {
		return
	}
	seq := p.ipToSeqV4(ip)
	p.v4.Write(func(s *v4State) { delete(s.inUse, seq) })
}

// InUseCount returns the number of currently allocated IPv4 addresses.
// Always 0 for IPv6 pools (stateless).
func (p *VNetPool) InUseCount() int {
	if p.v4 == nil {
		return 0
	}
	var n int
	p.v4.Read(func(s v4State) { n = len(s.inUse) })
	return n
}

func (p *VNetPool) ipToSeqV4(ip netip.Addr) uint32 {
	b4 := ip.As4()
	ipVal := uint32(b4[0])<<24 | uint32(b4[1])<<16 | uint32(b4[2])<<8 | uint32(b4[3])
	base4 := p.baseAddr.As4()
	baseVal := uint32(base4[0])<<24 | uint32(base4[1])<<16 | uint32(base4[2])<<8 | uint32(base4[3])
	return ipVal - baseVal
}

// NewVNetPool creates a single VNet pool for the given VNI and CIDR prefix.
// For v4 prefixes, seed controls the starting offset to spread allocations
// across operators. For v6, seed is ignored.
func NewVNetPool(vni common.VNI, prefix netip.Prefix, seed uint32) *VNetPool {
	p := &VNetPool{
		VNI:      vni,
		Prefix:   prefix,
		baseAddr: prefix.Addr(),
	}
	if !prefix.Addr().Is4() {
		return p
	}

	hostBits := 32 - prefix.Bits()
	usable := uint32(1<<hostBits) - 2
	offset := uint32(2)
	if usable > 0 {
		offset = 2 + (seed % usable)
	}
	var maxHost uint32
	if hostBits >= 32 {
		maxHost = ^uint32(0)
	} else {
		maxHost = (1 << hostBits) - 1
	}
	if offset < 2 {
		offset = 2
	}
	if offset > maxHost {
		offset = 2
	}
	p.v4 = common.WithGuard(v4State{
		next:    offset,
		inUse:   make(map[uint32]bool),
		maxHost: maxHost,
	})
	return p
}
