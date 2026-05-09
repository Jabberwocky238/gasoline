package operator

// Longest-prefix-match routing table for one VNI. The trie portion is
// adapted from WireGuard's common/allowedips.go (binary patricia trie,
// LPM lookup, MIT licensed). We store CIDs at trie nodes instead of
// Peers, and keep a parallel cid->prefix map so removal can be driven
// from either side and the structure stays bijective.

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"net/netip"
	"sync"

	"github.com/jabberwocky238/gasoline/protocol"
)

// dispatchRoute parses the args of a `route ...` gasoctl command and
// applies it to s. Returns the gasoctl reply line.
func (s *operatorState) dispatchRoute(args []string) string {
	if len(args) == 0 {
		return errReply("route: missing subcommand")
	}
	switch args[0] {
	case "set":
		if len(args) != 3 {
			return errReply("route set: usage 'route set <cid> <prefix>'")
		}
		cid, err := parseCID(args[1])
		if err != nil {
			return errReply(err.Error())
		}
		pfx, err := netip.ParsePrefix(args[2])
		if err != nil {
			return errReply(fmt.Sprintf("bad prefix %q: %v", args[2], err))
		}
		if err := s.routeSet(cid, pfx); err != nil {
			return errReply(err.Error())
		}
		return "OK"

	case "get":
		if len(args) != 2 {
			return errReply("route get: usage 'route get <cid>'")
		}
		cid, err := parseCID(args[1])
		if err != nil {
			return errReply(err.Error())
		}
		pfx, ok := s.routeGet(cid)
		if !ok {
			return errReply("not found")
		}
		return "OK " + pfx.String()

	case "del":
		if len(args) != 2 {
			return errReply("route del: usage 'route del <cid>'")
		}
		cid, err := parseCID(args[1])
		if err != nil {
			return errReply(err.Error())
		}
		s.routeDel(cid)
		return "OK"

	default:
		return errReply(fmt.Sprintf("route: unknown op %q", args[0]))
	}
}

// parseCID decodes a CID from gasoctl. Decimal by default, "0x..." for hex.
func parseCID(s string) (protocol.CID_Ty, error) { return protocol.ParseCID(s) }

func errReply(msg string) string { return "ERR " + msg }

type routingTrieNode struct {
	cid       protocol.CID_Ty
	hasCID    bool
	child     [2]*routingTrieNode
	cidr      uint8
	bitAtByte uint8 // cidr / 8
	bitAtShft uint8 // 7 - (cidr % 8)
	bits      []byte
}

func commonBits(a, b []byte) uint8 {
	if len(a) == 4 {
		x := binary.BigEndian.Uint32(a) ^ binary.BigEndian.Uint32(b)
		return uint8(bits.LeadingZeros32(x))
	}
	x1 := binary.BigEndian.Uint64(a) ^ binary.BigEndian.Uint64(b)
	if x1 != 0 {
		return uint8(bits.LeadingZeros64(x1))
	}
	x2 := binary.BigEndian.Uint64(a[8:]) ^ binary.BigEndian.Uint64(b[8:])
	return 64 + uint8(bits.LeadingZeros64(x2))
}

func (n *routingTrieNode) choose(ip []byte) byte {
	return (ip[n.bitAtByte] >> n.bitAtShft) & 1
}

func (n *routingTrieNode) maskSelf() {
	bytes := uint(n.cidr / 8)
	rem := n.cidr % 8
	for i := uint(0); i < uint(len(n.bits)); i++ {
		switch {
		case i < bytes:
		case i == bytes && rem != 0:
			n.bits[i] &= byte(0xFF) << (8 - rem)
		default:
			n.bits[i] = 0
		}
	}
}

// nodePlacement walks the trie following ip's bits, returning the
// deepest node whose prefix is a prefix of ip and whose cidr <= the
// requested cidr. exact == true iff that node's cidr equals cidr.
func (n *routingTrieNode) nodePlacement(ip []byte, cidr uint8) (parent *routingTrieNode, exact bool) {
	for n != nil && n.cidr <= cidr && commonBits(n.bits, ip) >= n.cidr {
		parent = n
		if parent.cidr == cidr {
			exact = true
			return
		}
		n = n.child[n.choose(ip)]
	}
	return
}

func newTrieNode(ip []byte, cidr uint8) *routingTrieNode {
	cp := append([]byte(nil), ip...)
	n := &routingTrieNode{
		bits:      cp,
		cidr:      cidr,
		bitAtByte: cidr / 8,
		bitAtShft: 7 - (cidr % 8),
	}
	n.maskSelf()
	return n
}

// insert places (ip, cidr, cid) into *root. If an exact node exists,
// its cid is replaced (and the old cid returned via prevCID/prevExact).
func insertCID(root **routingTrieNode, ip []byte, cidr uint8, cid protocol.CID_Ty) (prev protocol.CID_Ty, replaced bool) {
	if *root == nil {
		n := newTrieNode(ip, cidr)
		n.cid = cid
		n.hasCID = true
		*root = n
		return
	}

	node, exact := (*root).nodePlacement(ip, cidr)
	if exact {
		if node.hasCID {
			prev = node.cid
			replaced = true
		}
		node.cid = cid
		node.hasCID = true
		return
	}

	newNode := newTrieNode(ip, cidr)
	newNode.cid = cid
	newNode.hasCID = true

	var down *routingTrieNode
	if node == nil {
		down = *root
	} else {
		bit := node.choose(ip)
		down = node.child[bit]
		if down == nil {
			node.child[bit] = newNode
			return
		}
	}

	common := commonBits(down.bits, ip)
	if common < cidr {
		cidr = common
	}

	if newNode.cidr == cidr {
		newNode.child[newNode.choose(down.bits)] = down
		if node == nil {
			*root = newNode
		} else {
			node.child[node.choose(newNode.bits)] = newNode
		}
		return
	}

	branch := newTrieNode(newNode.bits, cidr)
	branch.child[branch.choose(down.bits)] = down
	branch.child[branch.choose(newNode.bits)] = newNode
	if node == nil {
		*root = branch
	} else {
		node.child[node.choose(branch.bits)] = branch
	}
	return
}

// lookupLPM walks the trie returning the cid attached to the deepest
// node whose prefix matches ip.
func (n *routingTrieNode) lookupLPM(ip []byte) (cid protocol.CID_Ty, ok bool) {
	size := uint8(len(ip))
	for n != nil && commonBits(n.bits, ip) >= n.cidr {
		if n.hasCID {
			cid = n.cid
			ok = true
		}
		if n.bitAtByte == size {
			break
		}
		n = n.child[n.choose(ip)]
	}
	return
}

// removeExact clears the cid on the node matching prefix exactly. This
// implementation does not prune empty internal nodes — the trie may
// retain branch nodes after deletion, which is fine for our scale.
func removeExact(root *routingTrieNode, ip []byte, cidr uint8) bool {
	node, exact := root.nodePlacement(ip, cidr)
	if !exact || node == nil || !node.hasCID {
		return false
	}
	var zero protocol.CID_Ty
	node.cid = zero
	node.hasCID = false
	return true
}

// vnetRoutingMap is the per-VNI cid<->prefix table with LPM lookup on
// the prefix side.
type vnetRoutingMap struct {
	mu       sync.RWMutex
	v4       *routingTrieNode
	v6       *routingTrieNode
	cidToPfx map[protocol.CID_Ty]netip.Prefix
}

func newVnetRoutingMap() *vnetRoutingMap {
	return &vnetRoutingMap{
		cidToPfx: make(map[protocol.CID_Ty]netip.Prefix),
	}
}

// Set installs cid <-> prefix. If cid had a different prefix, the old
// trie entry is removed; if prefix already mapped to a different cid,
// that cid's reverse entry is dropped so the structure stays bijective.
func (m *vnetRoutingMap) Set(cid protocol.CID_Ty, prefix netip.Prefix) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if oldPfx, ok := m.cidToPfx[cid]; ok && oldPfx != prefix {
		m.removeExactLocked(oldPfx)
	}

	cidr := uint8(prefix.Bits())
	addr := prefix.Addr()
	switch {
	case addr.Is4():
		ip := addr.As4()
		prev, replaced := insertCID(&m.v4, ip[:], cidr, cid)
		if replaced && prev != cid {
			delete(m.cidToPfx, prev)
		}
	case addr.Is6():
		ip := addr.As16()
		prev, replaced := insertCID(&m.v6, ip[:], cidr, cid)
		if replaced && prev != cid {
			delete(m.cidToPfx, prev)
		}
	default:
		return
	}
	m.cidToPfx[cid] = prefix
}

// LookupByCID returns the prefix bound to cid.
func (m *vnetRoutingMap) LookupByCID(cid protocol.CID_Ty) (netip.Prefix, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.cidToPfx[cid]
	return p, ok
}

// LookupByIP performs longest-prefix-match: returns the cid whose
// configured prefix is the longest one containing ip.
func (m *vnetRoutingMap) LookupByIP(ip netip.Addr) (protocol.CID_Ty, bool) {
	// fast path, no lock
	// m.mu.RLock()
	// defer m.mu.RUnlock()
	if ip.Is4() {
		b := ip.As4()
		return m.v4.lookupLPM(b[:])
	}
	if ip.Is6() {
		b := ip.As16()
		return m.v6.lookupLPM(b[:])
	}
	var zero protocol.CID_Ty
	return zero, false
}

// LookupByPrefix returns the cid bound to an exactly-matching prefix.
func (m *vnetRoutingMap) LookupByPrefix(prefix netip.Prefix) (protocol.CID_Ty, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	addr := prefix.Addr()
	cidr := uint8(prefix.Bits())
	var node *routingTrieNode
	var exact bool
	switch {
	case addr.Is4():
		if m.v4 == nil {
			break
		}
		ip := addr.As4()
		node, exact = m.v4.nodePlacement(ip[:], cidr)
	case addr.Is6():
		if m.v6 == nil {
			break
		}
		ip := addr.As16()
		node, exact = m.v6.nodePlacement(ip[:], cidr)
	}
	if !exact || node == nil || !node.hasCID {
		var zero protocol.CID_Ty
		return zero, false
	}
	return node.cid, true
}

// DeleteByCID removes the binding keyed by cid.
func (m *vnetRoutingMap) DeleteByCID(cid protocol.CID_Ty) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pfx, ok := m.cidToPfx[cid]
	if !ok {
		return
	}
	m.removeExactLocked(pfx)
	delete(m.cidToPfx, cid)
}

// DeleteByPrefix removes the binding keyed by prefix.
func (m *vnetRoutingMap) DeleteByPrefix(prefix netip.Prefix) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cid, ok := m.lookupExactLocked(prefix)
	if !ok {
		return
	}
	m.removeExactLocked(prefix)
	delete(m.cidToPfx, cid)
}

// Len returns the number of cid<->prefix bindings.
func (m *vnetRoutingMap) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.cidToPfx)
}

func (m *vnetRoutingMap) removeExactLocked(prefix netip.Prefix) {
	addr := prefix.Addr()
	cidr := uint8(prefix.Bits())
	switch {
	case addr.Is4() && m.v4 != nil:
		ip := addr.As4()
		removeExact(m.v4, ip[:], cidr)
	case addr.Is6() && m.v6 != nil:
		ip := addr.As16()
		removeExact(m.v6, ip[:], cidr)
	}
}

func (m *vnetRoutingMap) lookupExactLocked(prefix netip.Prefix) (protocol.CID_Ty, bool) {
	addr := prefix.Addr()
	cidr := uint8(prefix.Bits())
	var node *routingTrieNode
	var exact bool
	switch {
	case addr.Is4() && m.v4 != nil:
		ip := addr.As4()
		node, exact = m.v4.nodePlacement(ip[:], cidr)
	case addr.Is6() && m.v6 != nil:
		ip := addr.As16()
		node, exact = m.v6.nodePlacement(ip[:], cidr)
	}
	if !exact || node == nil || !node.hasCID {
		var zero protocol.CID_Ty
		return zero, false
	}
	return node.cid, true
}
