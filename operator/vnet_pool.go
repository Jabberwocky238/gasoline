package operator

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/jabberwocky238/gasoline/common"
)

// VNetPool manages IP allocation for a single VNet.
//
// IPv4: sequential pool with recycle list (state-tracking).
// IPv6: deterministic derivation from (SessionID, VNI) — no state required.
//       ReserveIP / UnreserveIP / ReleaseIP are no-ops on v6 pools since
//       there is no shared allocation table to coordinate.
type VNetPool struct {
	VNI      common.VNI
	Prefix   netip.Prefix
	baseAddr netip.Addr

	// IPv4-only state
	mu      sync.Mutex
	next    uint32          // next sequence to try
	freed   []uint32        // recycled sequences
	inUse   map[uint32]bool // all known in-use sequences (local + remote)
	maxHost uint32          // max usable host count
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
	p.mu.Lock()
	defer p.mu.Unlock()

	// Try freed list first
	for len(p.freed) > 0 {
		seq := p.freed[len(p.freed)-1]
		p.freed = p.freed[:len(p.freed)-1]
		if !p.inUse[seq] {
			ip := addToAddrV4(p.baseAddr, seq)
			p.inUse[seq] = true
			return ip, nil
		}
	}

	// Scan from p.next, wrapping around once
	start := p.next
	wrapped := false
	for {
		seq := p.next
		p.next++
		if p.next > p.maxHost {
			p.next = 2 // wrap around
		}

		if !wrapped && p.next == start {
			return netip.Addr{}, fmt.Errorf("IP pool exhausted for vni %s", p.VNI)
		}
		if p.next == start {
			wrapped = true
		}

		if p.inUse[seq] {
			continue
		}

		ip := addToAddrV4(p.baseAddr, seq)
		if !p.Prefix.Contains(ip) {
			continue
		}

		p.inUse[seq] = true
		return ip, nil
	}
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

	// Overwrite host portion of base with hash bytes.
	// networkBytes = bits/8; networkBitRemainder handles non-byte-aligned prefixes.
	networkBytes := bits / 8
	remainder := bits % 8

	if networkBytes < 16 {
		// Preserve any partial byte at the boundary.
		if remainder != 0 {
			mask := byte(0xFF << (8 - remainder))
			base[networkBytes] = (base[networkBytes] & mask) | (sum[networkBytes] &^ mask)
			networkBytes++
		}
		// Fill full host bytes from hash.
		for i := networkBytes; i < 16; i++ {
			base[i] = sum[i-(bits/8)]
		}
	}
	return netip.AddrFrom16(base)
}

// ReleaseIP returns an IPv4 address back to the pool. No-op for IPv6.
func (p *VNetPool) ReleaseIP(ip netip.Addr) {
	if !ip.Is4() {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	seq := p.ipToSeqV4(ip)
	if !p.inUse[seq] {
		return
	}
	delete(p.inUse, seq)
	p.freed = append(p.freed, seq)
}

// ReserveIP marks an IPv4 address as in-use. No-op for IPv6 (stateless).
func (p *VNetPool) ReserveIP(ip netip.Addr) {
	if !ip.Is4() {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.inUse[p.ipToSeqV4(ip)] = true
}

// UnreserveIP removes an IPv4 reservation. No-op for IPv6.
func (p *VNetPool) UnreserveIP(ip netip.Addr) {
	if !ip.Is4() {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.inUse, p.ipToSeqV4(ip))
}

// InUseCount returns the number of currently allocated IPv4 addresses.
// Always 0 for IPv6 pools (stateless).
func (p *VNetPool) InUseCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.inUse)
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
		// IPv6: no state needed
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
	p.next = offset
	p.inUse = make(map[uint32]bool)
	p.maxHost = maxHost
	return p
}

// --------------- VNetPoolMap ---------------

type VNetPoolMap struct {
	mu    sync.RWMutex
	pools map[common.VNI]*VNetPool
}

func NewVNetPoolMap() *VNetPoolMap {
	return &VNetPoolMap{pools: make(map[common.VNI]*VNetPool)}
}

// ParseVNetPools parses "vni:CIDR;vni:CIDR;..." into a VNetPoolMap.
// seed is used to spread starting offsets across operators (IPv4 only).
func ParseVNetPools(network string, seed uint32) (*VNetPoolMap, error) {
	m := &VNetPoolMap{pools: make(map[common.VNI]*VNetPool)}

	for _, entry := range strings.Split(network, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid network entry (expected vni:CIDR): %s", entry)
		}
		vni, err := common.ParseVNI(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid vni %q: %w", parts[0], err)
		}

		prefix, err := netip.ParsePrefix(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", parts[1], err)
		}

		m.pools[vni] = NewVNetPool(vni, prefix, seed)
	}

	if len(m.pools) == 0 {
		return nil, fmt.Errorf("no network configured")
	}
	return m, nil
}

// Get returns a pool by VNI.
func (m *VNetPoolMap) Get(vni common.VNI) (*VNetPool, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.pools[vni]
	return p, ok
}

// Add inserts or replaces a pool for the given VNI.
func (m *VNetPoolMap) Add(vni common.VNI, pool *VNetPool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pools[vni] = pool
}

// Remove deletes a pool by VNI. Returns true if it existed.
func (m *VNetPoolMap) Remove(vni common.VNI) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.pools[vni]
	delete(m.pools, vni)
	return ok
}

// All returns a snapshot of all pools for iteration.
func (m *VNetPoolMap) All() map[common.VNI]*VNetPool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cp := make(map[common.VNI]*VNetPool, len(m.pools))
	for k, v := range m.pools {
		cp[k] = v
	}
	return cp
}

func addToAddrV4(base netip.Addr, offset uint32) netip.Addr {
	b4 := base.As4()
	val := uint32(b4[0])<<24 | uint32(b4[1])<<16 | uint32(b4[2])<<8 | uint32(b4[3])
	val += offset
	return netip.AddrFrom4([4]byte{byte(val >> 24), byte(val >> 16), byte(val >> 8), byte(val)})
}
