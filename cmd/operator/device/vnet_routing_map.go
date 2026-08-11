package operator

// Longest-prefix-match routing table for one VNI. The trie portion is
// adapted from WireGuard's common/allowedips.go (binary patricia trie,
// LPM lookup, MIT licensed). Each leaf carries a RouteTarget that is
// EITHER a local client (CID) OR a remote peer operator (UUID); LPM
// lookups return that tagged target so the caller knows whether to
// forward locally or to ship the frame off to another operator.

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

// --------------- RouteTarget ---------------

// RouteTargetKind discriminates between a local client and a remote
// peer operator.
type RouteTargetKind uint8

const (
	// RouteTargetClient: the prefix is owned by a client that handshakes
	// directly with this operator. The CID names that client.
	RouteTargetClient RouteTargetKind = iota

	// RouteTargetOperator: the prefix is owned by a client that
	// handshakes with a different operator; OpUUID names that operator
	// (we look up its data-plane endpoint from operatorState.Peers).
	RouteTargetOperator
)

// RouteTarget is the resolved owner of a prefix.
type RouteTarget struct {
	Kind   RouteTargetKind
	CID    protocol.CID_Ty // valid when Kind == RouteTargetClient
	OpUUID [16]byte        // valid when Kind == RouteTargetOperator
}

// --------------- trie ---------------

type routingTrieNode struct {
	target    RouteTarget
	hasTarget bool
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

// insertTarget places (ip, cidr, target) into *root. If an exact node
// already exists, its target is replaced (and the old one returned).
func insertTarget(root **routingTrieNode, ip []byte, cidr uint8, target RouteTarget) (prev RouteTarget, replaced bool) {
	if *root == nil {
		n := newTrieNode(ip, cidr)
		n.target = target
		n.hasTarget = true
		*root = n
		return
	}

	node, exact := (*root).nodePlacement(ip, cidr)
	if exact {
		if node.hasTarget {
			prev = node.target
			replaced = true
		}
		node.target = target
		node.hasTarget = true
		return
	}

	newNode := newTrieNode(ip, cidr)
	newNode.target = target
	newNode.hasTarget = true

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

// lookupLPM walks the trie returning the target attached to the
// deepest node whose prefix matches ip.
func (n *routingTrieNode) lookupLPM(ip []byte) (target RouteTarget, ok bool) {
	size := uint8(len(ip))
	for n != nil && commonBits(n.bits, ip) >= n.cidr {
		if n.hasTarget {
			target = n.target
			ok = true
		}
		if n.bitAtByte == size {
			break
		}
		n = n.child[n.choose(ip)]
	}
	return
}

// removeExact clears the target on the node matching prefix exactly.
// Empty internal nodes are not pruned (fine at our scale).
func removeExact(root *routingTrieNode, ip []byte, cidr uint8) bool {
	node, exact := root.nodePlacement(ip, cidr)
	if !exact || node == nil || !node.hasTarget {
		return false
	}
	node.target = RouteTarget{}
	node.hasTarget = false
	return true
}

// --------------- vnetRoutingMap ---------------

// vnetRoutingMap is the per-VNI prefix -> (client | operator) table
// with LPM lookup on the prefix side and bidirectional reverse maps
// keyed by client CID and peer operator UUID.
type vnetRoutingMap struct {
	mu        sync.RWMutex
	v4        *routingTrieNode
	v6        *routingTrieNode
	cidToPfx  map[protocol.CID_Ty]netip.Prefix
	uuidToPfx map[[16]byte]netip.Prefix
}

func newVnetRoutingMap() *vnetRoutingMap {
	return &vnetRoutingMap{
		cidToPfx:  make(map[protocol.CID_Ty]netip.Prefix),
		uuidToPfx: make(map[[16]byte]netip.Prefix),
	}
}

// Set is a back-compat alias for SetClient.
func (m *vnetRoutingMap) Set(cid protocol.CID_Ty, prefix netip.Prefix) {
	m.SetClient(cid, prefix)
}

// SetClient binds cid <-> prefix as a local client route.
func (m *vnetRoutingMap) SetClient(cid protocol.CID_Ty, prefix netip.Prefix) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setLocked(RouteTarget{Kind: RouteTargetClient, CID: cid}, prefix)
}

// SetOperator binds peer-operator-uuid <-> prefix as a remote route.
func (m *vnetRoutingMap) SetOperator(uuid [16]byte, prefix netip.Prefix) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setLocked(RouteTarget{Kind: RouteTargetOperator, OpUUID: uuid}, prefix)
}

// setLocked is the shared write path. Callers hold m.mu.
func (m *vnetRoutingMap) setLocked(target RouteTarget, prefix netip.Prefix) {
	// Remove any stale binding for this target identity.
	switch target.Kind {
	case RouteTargetClient:
		if oldPfx, ok := m.cidToPfx[target.CID]; ok && oldPfx != prefix {
			m.removeExactLocked(oldPfx)
		}
	case RouteTargetOperator:
		if oldPfx, ok := m.uuidToPfx[target.OpUUID]; ok && oldPfx != prefix {
			m.removeExactLocked(oldPfx)
		}
	}

	cidr := uint8(prefix.Bits())
	addr := prefix.Addr()
	switch {
	case addr.Is4():
		ip := addr.As4()
		prev, replaced := insertTarget(&m.v4, ip[:], cidr, target)
		if replaced {
			m.dropReverseLocked(prev)
		}
	case addr.Is6():
		ip := addr.As16()
		prev, replaced := insertTarget(&m.v6, ip[:], cidr, target)
		if replaced {
			m.dropReverseLocked(prev)
		}
	default:
		return
	}

	switch target.Kind {
	case RouteTargetClient:
		m.cidToPfx[target.CID] = prefix
	case RouteTargetOperator:
		m.uuidToPfx[target.OpUUID] = prefix
	}
}

// dropReverseLocked removes a stale identity → prefix entry whose
// trie slot has just been overwritten.
func (m *vnetRoutingMap) dropReverseLocked(t RouteTarget) {
	switch t.Kind {
	case RouteTargetClient:
		delete(m.cidToPfx, t.CID)
	case RouteTargetOperator:
		delete(m.uuidToPfx, t.OpUUID)
	}
}

// LookupByCID returns the prefix bound to a client cid.
func (m *vnetRoutingMap) LookupByCID(cid protocol.CID_Ty) (netip.Prefix, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.cidToPfx[cid]
	return p, ok
}

// LookupByOpUUID returns the prefix bound to a peer operator UUID.
func (m *vnetRoutingMap) LookupByOpUUID(uuid [16]byte) (netip.Prefix, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.uuidToPfx[uuid]
	return p, ok
}

// LookupByIP performs longest-prefix-match: returns the RouteTarget
// (either a local client CID or a remote operator UUID) whose configured
// prefix is the longest one containing ip.
func (m *vnetRoutingMap) LookupByIP(ip netip.Addr) (RouteTarget, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if ip.Is4() {
		b := ip.As4()
		return m.v4.lookupLPM(b[:])
	}
	if ip.Is6() {
		b := ip.As16()
		return m.v6.lookupLPM(b[:])
	}
	return RouteTarget{}, false
}

// LookupByPrefix returns the target bound to an exactly-matching prefix.
func (m *vnetRoutingMap) LookupByPrefix(prefix netip.Prefix) (RouteTarget, bool) {
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
	if !exact || node == nil || !node.hasTarget {
		return RouteTarget{}, false
	}
	return node.target, true
}

// DeleteByCID removes the binding keyed by client cid.
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

// DeleteByOpUUID removes the binding keyed by peer operator UUID.
func (m *vnetRoutingMap) DeleteByOpUUID(uuid [16]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pfx, ok := m.uuidToPfx[uuid]
	if !ok {
		return
	}
	m.removeExactLocked(pfx)
	delete(m.uuidToPfx, uuid)
}

// DeleteByPrefix removes the binding keyed by prefix (whichever target
// it owned).
func (m *vnetRoutingMap) DeleteByPrefix(prefix netip.Prefix) {
	m.mu.Lock()
	defer m.mu.Unlock()
	target, ok := m.lookupExactLocked(prefix)
	if !ok {
		return
	}
	m.removeExactLocked(prefix)
	m.dropReverseLocked(target)
}

// Len returns the total number of bindings (clients + operators).
func (m *vnetRoutingMap) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.cidToPfx) + len(m.uuidToPfx)
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

func (m *vnetRoutingMap) lookupExactLocked(prefix netip.Prefix) (RouteTarget, bool) {
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
	if !exact || node == nil || !node.hasTarget {
		return RouteTarget{}, false
	}
	return node.target, true
}
