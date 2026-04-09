package operator

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/jabberwocky238/gasoline/common"
)

// VNetPool manages IP allocation for a single VNet.
type VNetPool struct {
	VNetID   [common.VNetIDLen]byte
	Prefix   netip.Prefix
	baseAddr netip.Addr

	mu      sync.Mutex
	next    uint32          // next sequence to try
	freed   []uint32        // recycled sequences
	inUse   map[uint32]bool // all known in-use sequences (local + remote)
	maxHost uint32          // max usable host count
}

// AllocateIP returns the next available IP in this pool.
// Wraps around the pool to find a free slot.
func (p *VNetPool) AllocateIP() (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Try freed list first
	for len(p.freed) > 0 {
		seq := p.freed[len(p.freed)-1]
		p.freed = p.freed[:len(p.freed)-1]
		if !p.inUse[seq] {
			ip := addToAddr(p.baseAddr, seq)
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
			// Full loop, pool exhausted
			return netip.Addr{}, fmt.Errorf("IP pool exhausted for vnet %x", p.VNetID)
		}
		if p.next == start {
			wrapped = true
		}

		if p.inUse[seq] {
			continue
		}

		ip := addToAddr(p.baseAddr, seq)
		if !p.Prefix.Contains(ip) {
			continue
		}

		p.inUse[seq] = true
		return ip, nil
	}
}

// ReleaseIP returns an IP back to the pool for reuse (local allocations only).
func (p *VNetPool) ReleaseIP(ip netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()

	seq := p.ipToSeq(ip)
	if !p.inUse[seq] {
		return
	}
	delete(p.inUse, seq)
	p.freed = append(p.freed, seq)
}

// ReserveIP marks an IP as in-use (allocated by a remote operator).
func (p *VNetPool) ReserveIP(ip netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.inUse[p.ipToSeq(ip)] = true
}

// UnreserveIP removes a remote reservation.
func (p *VNetPool) UnreserveIP(ip netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.inUse, p.ipToSeq(ip))
}

// InUseCount returns the number of currently allocated IPs.
func (p *VNetPool) InUseCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.inUse)
}

func (p *VNetPool) ipToSeq(ip netip.Addr) uint32 {
	b4 := ip.As4()
	ipVal := uint32(b4[0])<<24 | uint32(b4[1])<<16 | uint32(b4[2])<<8 | uint32(b4[3])
	base4 := p.baseAddr.As4()
	baseVal := uint32(base4[0])<<24 | uint32(base4[1])<<16 | uint32(base4[2])<<8 | uint32(base4[3])
	return ipVal - baseVal
}

// --------------- VNetPoolMap ---------------

type VNetPoolMap struct {
	pools map[[common.VNetIDLen]byte]*VNetPool
}

// ParseVNetPools parses "vnetID:CIDR;vnetID:CIDR;..." into a VNetPoolMap.
// seed is used to spread starting offsets across operators (typically UUID bytes).
func ParseVNetPools(network string, seed uint32) (*VNetPoolMap, error) {
	m := &VNetPoolMap{pools: make(map[[common.VNetIDLen]byte]*VNetPool)}

	for _, entry := range strings.Split(network, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid network entry (expected vnetID:CIDR): %s", entry)
		}
		vnetNum, err := strconv.ParseUint(parts[0], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid vnet ID %q: %w", parts[0], err)
		}
		var vnetIDBytes [common.VNetIDLen]byte
		binary.BigEndian.PutUint64(vnetIDBytes[8:], vnetNum)
		vnetID := vnetIDBytes

		prefix, err := netip.ParsePrefix(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", parts[1], err)
		}

		// Spread starting offset: seed modulo usable range, minimum 2
		hostBits := 32 - prefix.Bits()
		usable := uint32(1<<hostBits) - 2 // exclude .0 and .1
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
			offset = 2 // .0=network, .1=gateway
		}
		if offset > maxHost {
			offset = 2
		}
		m.pools[vnetID] = &VNetPool{
			VNetID:   vnetID,
			Prefix:   prefix,
			baseAddr: prefix.Addr(),
			next:     offset,
			inUse:    make(map[uint32]bool),
			maxHost:  maxHost,
		}
	}

	if len(m.pools) == 0 {
		return nil, fmt.Errorf("no network configured")
	}
	return m, nil
}

// Get returns a pool by VNetID.
func (m *VNetPoolMap) Get(vnetID [common.VNetIDLen]byte) (*VNetPool, bool) {
	p, ok := m.pools[vnetID]
	return p, ok
}

// All returns all pools for iteration.
func (m *VNetPoolMap) All() map[[common.VNetIDLen]byte]*VNetPool {
	return m.pools
}

func addToAddr(base netip.Addr, offset uint32) netip.Addr {
	b4 := base.As4()
	val := uint32(b4[0])<<24 | uint32(b4[1])<<16 | uint32(b4[2])<<8 | uint32(b4[3])
	val += offset
	return netip.AddrFrom4([4]byte{byte(val >> 24), byte(val >> 16), byte(val >> 8), byte(val)})
}
