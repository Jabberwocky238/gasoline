package fakeip

import (
	"container/list"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
)

// PoolConfig is the construction input for Pool. Both Range and Size must be
// set; TTL controls nothing here (it is purely a DNS-response concern and
// lives on the Server), so it's not part of this struct.
type PoolConfig struct {
	// Range is the IP block from which fake addresses are drawn. Must be
	// IPv4 for now (198.18.0.0/15 is the canonical choice). The first and
	// last address of the range are skipped (network / broadcast).
	Range netip.Prefix

	// Size caps how many live domain↔IP bindings the pool holds. When the
	// cap is hit a new allocation evicts the least-recently-used entry.
	// Must be >= 1 and <= usable addresses in Range.
	Size int
}

// Pool is a thread-safe LRU allocator that maps domain names to synthetic
// IP addresses and back. The mapping is stable for the entry's lifetime in
// the LRU: once example.com → 198.18.0.7 is established, the same pair
// holds until eviction, so any in-flight connection targeting 198.18.0.7
// can be recovered back to example.com.
type Pool struct {
	mu sync.Mutex

	rangeP netip.Prefix
	size   int

	// first / last are the first and last *usable* (non-network,
	// non-broadcast) addresses in rangeP as uint32.
	first uint32
	last  uint32
	// next is the hint for the next fresh allocation; walks first..last
	// and wraps. Used only when byIP has room and we avoid colliding
	// with live entries by probing.
	next uint32

	byName map[string]*entry
	byIP   map[netip.Addr]*entry
	lru    *list.List // front = MRU; Value = *entry
}

type entry struct {
	ip       netip.Addr
	domain   string
	lruNode  *list.Element
}

// New constructs a Pool. Returns an error on empty / non-v4 / too-small
// range or an invalid Size.
func New(cfg PoolConfig) (*Pool, error) {
	if !cfg.Range.IsValid() {
		return nil, errors.New("fakeip: Range required")
	}
	if !cfg.Range.Addr().Is4() {
		return nil, errors.New("fakeip: only IPv4 ranges supported for now")
	}
	if cfg.Size < 1 {
		return nil, errors.New("fakeip: Size must be >= 1")
	}
	first, last, ok := rangeBounds(cfg.Range)
	if !ok {
		return nil, fmt.Errorf("fakeip: Range %s has no usable addresses", cfg.Range)
	}
	usable := int(last - first + 1)
	if cfg.Size > usable {
		return nil, fmt.Errorf("fakeip: Size %d exceeds usable addresses in %s (%d)", cfg.Size, cfg.Range, usable)
	}
	return &Pool{
		rangeP: cfg.Range,
		size:   cfg.Size,
		first:  first,
		last:   last,
		next:   first,
		byName: make(map[string]*entry, cfg.Size),
		byIP:   make(map[netip.Addr]*entry, cfg.Size),
		lru:    list.New(),
	}, nil
}

// Lookup returns the fake IP for `domain`, allocating a new one on first
// sight. The `domain` is lowercased and trailing-dot-stripped to make
// "Example.COM" and "example.com." share a single entry.
//
// If the pool is full, the least-recently-used entry is evicted to make
// room. The caller should size the pool large enough that eviction is rare
// relative to the DNS TTL advertised on the wire.
func (p *Pool) Lookup(domain string) netip.Addr {
	key := canonicalize(domain)
	p.mu.Lock()
	defer p.mu.Unlock()

	if e, ok := p.byName[key]; ok {
		p.lru.MoveToFront(e.lruNode)
		return e.ip
	}

	if p.lru.Len() >= p.size {
		p.evictOldestLocked()
	}
	ip := p.pickFreeIPLocked()
	e := &entry{ip: ip, domain: key}
	e.lruNode = p.lru.PushFront(e)
	p.byName[key] = e
	p.byIP[ip] = e
	return ip
}

// Reverse returns the domain previously bound to `ip`. Returns ("", false)
// if the address is unknown or outside the configured range.
func (p *Pool) Reverse(ip netip.Addr) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.byIP[ip]
	if !ok {
		return "", false
	}
	p.lru.MoveToFront(e.lruNode)
	return e.domain, true
}

// Contains reports whether ip falls inside the pool's range.
func (p *Pool) Contains(ip netip.Addr) bool {
	return p.rangeP.Contains(ip)
}

// Len returns the current number of bindings.
func (p *Pool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lru.Len()
}

// ---- internals ------------------------------------------------------------

func (p *Pool) evictOldestLocked() {
	back := p.lru.Back()
	if back == nil {
		return
	}
	e := back.Value.(*entry)
	p.lru.Remove(back)
	delete(p.byName, e.domain)
	delete(p.byIP, e.ip)
}

// pickFreeIPLocked advances the next pointer until it finds an address not
// currently bound in byIP and returns it. Because the caller has already
// evicted if we were at capacity, at least one slot is guaranteed free, so
// this walk is bounded by (last-first+1) iterations in the worst case —
// typically it finds a free slot on the first try thanks to the rolling
// `next` cursor.
func (p *Pool) pickFreeIPLocked() netip.Addr {
	start := p.next
	for {
		candidate := uint32ToAddr(p.next)
		p.advanceLocked()
		if _, taken := p.byIP[candidate]; !taken {
			return candidate
		}
		if p.next == start {
			// Should be impossible given the capacity pre-check; the range
			// is fully saturated and the caller forgot to evict.
			panic("fakeip: pool saturation invariant violated")
		}
	}
}

func (p *Pool) advanceLocked() {
	if p.next == p.last {
		p.next = p.first
	} else {
		p.next++
	}
}

// ---- helpers --------------------------------------------------------------

// rangeBounds returns the first and last usable addresses of an IPv4
// prefix as uint32. For /31 and /32 all addresses are considered usable
// (following modern practice); for larger prefixes the network and
// broadcast addresses are excluded.
func rangeBounds(p netip.Prefix) (first, last uint32, ok bool) {
	if !p.Addr().Is4() {
		return 0, 0, false
	}
	bits := p.Bits()
	addr := addrToUint32(p.Masked().Addr())
	hostBits := 32 - bits
	if hostBits > 31 {
		return 0, 0, false
	}
	size := uint32(1) << hostBits
	if size <= 2 && hostBits <= 1 {
		return addr, addr + size - 1, size > 0
	}
	return addr + 1, addr + size - 2, true
}

func addrToUint32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

func uint32ToAddr(u uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], u)
	return netip.AddrFrom4(b)
}

func canonicalize(domain string) string {
	return strings.ToLower(strings.TrimSuffix(domain, "."))
}
