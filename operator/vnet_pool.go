package operator

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
)

// VNetPool manages IP allocation for a single VNet.
type VNetPool struct {
	VNetID   VNetIDType
	Prefix   netip.Prefix
	baseAddr netip.Addr

	mu      sync.Mutex
	next    uint32   // next sequence to try (starts at 2: .0=network, .1=gateway)
	freed   []uint32 // recycled sequences, reused first
	inUse   map[uint32]bool
	maxHost uint32 // max usable host count in this prefix
}

func newVNetPool(vnetID VNetIDType, prefix netip.Prefix) *VNetPool {
	bits := prefix.Bits()
	hostBits := 32 - bits
	var maxHost uint32
	if hostBits >= 32 {
		maxHost = ^uint32(0)
	} else {
		maxHost = (1 << hostBits) - 1 // e.g. /24 → 255
	}
	return &VNetPool{
		VNetID:   vnetID,
		Prefix:   prefix,
		baseAddr: prefix.Addr(),
		next:     2,
		inUse:    make(map[uint32]bool),
		maxHost:  maxHost,
	}
}

// AllocateIP returns the next available IP in this pool.
func (p *VNetPool) AllocateIP() (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var seq uint32

	if len(p.freed) > 0 {
		// Reuse a recycled sequence
		seq = p.freed[len(p.freed)-1]
		p.freed = p.freed[:len(p.freed)-1]
	} else {
		// Allocate a new sequence
		if p.next > p.maxHost {
			return netip.Addr{}, fmt.Errorf("IP pool exhausted for vnet %x", p.VNetID)
		}
		seq = p.next
		p.next++
	}

	ip := common.AddToAddr(p.baseAddr, seq)
	if !p.Prefix.Contains(ip) {
		return netip.Addr{}, fmt.Errorf("IP pool exhausted for vnet %x", p.VNetID)
	}

	p.inUse[seq] = true
	return ip, nil
}

// ReleaseIP returns an IP back to the pool for reuse.
func (p *VNetPool) ReleaseIP(ip netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()

	b4 := ip.As4()
	ipVal := uint32(b4[0])<<24 | uint32(b4[1])<<16 | uint32(b4[2])<<8 | uint32(b4[3])
	base4 := p.baseAddr.As4()
	baseVal := uint32(base4[0])<<24 | uint32(base4[1])<<16 | uint32(base4[2])<<8 | uint32(base4[3])
	seq := ipVal - baseVal

	if !p.inUse[seq] {
		return
	}
	delete(p.inUse, seq)
	p.freed = append(p.freed, seq)
}

// InUseCount returns the number of currently allocated IPs.
func (p *VNetPool) InUseCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.inUse)
}

// VNetPoolMap manages multiple VNet pools.
type VNetPoolMap struct {
	pools map[VNetIDType]*VNetPool
}

// ParseVNetPools parses "vnetID:CIDR;vnetID:CIDR;..." into a VNetPoolMap.
func ParseVNetPools(network string) (*VNetPoolMap, error) {
	m := &VNetPoolMap{pools: make(map[VNetIDType]*VNetPool)}

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
		vnetID := VNetIDType(common.EncodeVNetID(vnetNum))

		prefix, err := netip.ParsePrefix(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", parts[1], err)
		}

		m.pools[vnetID] = newVNetPool(vnetID, prefix)
	}

	if len(m.pools) == 0 {
		return nil, fmt.Errorf("no network configured")
	}
	return m, nil
}

// Get returns a pool by VNetID.
func (m *VNetPoolMap) Get(vnetID VNetIDType) (*VNetPool, bool) {
	p, ok := m.pools[vnetID]
	return p, ok
}

// All returns all pools for iteration.
func (m *VNetPoolMap) All() map[VNetIDType]*VNetPool {
	return m.pools
}

// MakeConfigFunc creates a protocol.ConfigFunc that allocates IPs from the correct VNet pool.
func MakeConfigFunc(pools *VNetPoolMap, serverPub protocol.PublicKey, auth protocol.ServerAuthenticator) protocol.ConfigFunc {
	return func(clientID [16]byte) (*protocol.SessionConfig, error) {
		var vnetID VNetIDType
		var sessionID [16]byte
		if noauth, ok := auth.(*protocol.NoAuthServer); ok {
			vnetID = VNetIDType(noauth.LastVNetID)
			sessionID = noauth.LastSessionID
		}

		pool, ok := pools.Get(vnetID)
		if !ok {
			return nil, fmt.Errorf("unknown vnet %x", vnetID)
		}

		clientIP, err := pool.AllocateIP()
		if err != nil {
			return nil, err
		}

		clientPriv, err := protocol.NewPrivateKey()
		if err != nil {
			return nil, err
		}

		return &protocol.SessionConfig{
			SessionID:        sessionID,
			ClientPrivateKey: clientPriv,
			ServerPublicKey:  serverPub,
			IPPrefix:         netip.PrefixFrom(clientIP, 32),
			AllowedRanges:    []netip.Prefix{pool.Prefix},
		}, nil
	}
}
