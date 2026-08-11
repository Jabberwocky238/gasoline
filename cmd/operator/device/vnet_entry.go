package operator

import (
	"net/netip"
	"sync"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/dataframe"
	"github.com/jabberwocky238/gasoline/protocol/message"
	"github.com/jabberwocky238/gasoline/protocol/noise"
)

// vniEntry holds per-VNI runtime state: the active client set, an O(1)
// SessionID index over those clients, the routing table, the Noise
// authorization set, and the fixed-IP preset map.
type vniEntry struct {
	mu sync.RWMutex

	// authorizedKeys is the set of static public keys allowed on this VNI.
	// A key not in the set is rejected — there is no open/noauth mode.
	// Seeded from config; the Raft-backed key table (PRD §2.2) supersedes
	// this once consensus is wired into the handshake path.
	authorizedKeys map[noise.PublicKey]struct{}

	// presetIP pins a pubkey to a fixed IP (PRD §4.5). Consulted by the
	// allocator's Preclaim.
	presetIP map[noise.PublicKey]netip.Prefix

	clients            map[uint32]*PeerClient                // keyed by SessionIndex
	clientsBySessionID map[protocol.SessionID_Ty]*PeerClient // hot-path index for forwardFrame

	routingMap *vnetRoutingMap

	// peers is the operator's peer table; forwardFrame consults it when
	// LookupByIP returns a RouteTargetOperator. Set by the owning
	// operatorState at registration time.
	peers *PeerTable
	vni   protocol.VNI_Ty
}

func newVniEntry(authorizedKeys map[noise.PublicKey]struct{}) *vniEntry {
	if authorizedKeys == nil {
		authorizedKeys = make(map[noise.PublicKey]struct{})
	}
	return &vniEntry{
		authorizedKeys:     authorizedKeys,
		clients:            make(map[uint32]*PeerClient),
		clientsBySessionID: make(map[protocol.SessionID_Ty]*PeerClient),
		routingMap:         newVnetRoutingMap(),
	}
}

// authorized reports whether pubkey may join this VNI. There is no "open"
// mode: a key absent from the table is rejected. Identity-by-key is the only
// admission scheme — noauth/hmac/userpass were removed wholesale.
func (v *vniEntry) authorized(pubkey noise.PublicKey) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	_, ok := v.authorizedKeys[pubkey]
	return ok
}

func (v *vniEntry) addClient(cp *PeerClient) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.clients[cp.sc.SessionIndex] = cp
	v.clientsBySessionID[cp.sc.SessionID] = cp
}

func (v *vniEntry) removeClient(sessionIndex uint32) {
	v.mu.Lock()
	defer v.mu.Unlock()
	cp, ok := v.clients[sessionIndex]
	if !ok {
		return
	}
	delete(v.clients, sessionIndex)
	// Only drop the index entry if it still points at *this* client; a
	// SessionID re-bound to a fresh session must not be cleared by an old
	// session's teardown.
	if cur, ok := v.clientsBySessionID[cp.sc.SessionID]; ok && cur == cp {
		delete(v.clientsBySessionID, cp.sc.SessionID)
	}
}

// Clients returns a snapshot copy of the per-VNI client set.
func (v *vniEntry) Clients() []*PeerClient {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]*PeerClient, 0, len(v.clients))
	for _, cp := range v.clients {
		out = append(out, cp)
	}
	return out
}

// forwardFrame routes one DECRYPTED IP packet read from src (PRD §5.4.1: the PE
// decrypts, then routes on the plaintext dst IP).
//
//   - Version 3 (keepalive): reflect a sealed v3 packet back to src and stop.
//   - Version 4/6: LPM dst → RouteTarget.
//   - RouteTargetClient: O(1) SessionID lookup, RE-SEAL the IP packet under the
//     destination's session and write it (each CE↔PE leg has its own keys).
//   - RouteTargetOperator: ship the plaintext IP packet over the PE↔PE underlay
//     (underlay is unencrypted by design, PRD §7.5); the target PE re-seals for
//     its local client.
//   - Other versions: silently drop.
func (v *vniEntry) forwardFrame(pkt []byte, src *PeerClient) error {
	if len(pkt) < 1 {
		return nil
	}
	version := pkt[0] >> 4

	var dst netip.Addr
	switch version {
	case 3:
		if src == nil || src.closed.Load() {
			return nil
		}
		return writeSealedTo(src, buildKeepaliveReply())
	case 4:
		if len(pkt) < 20 {
			return nil
		}
		var b [4]byte
		copy(b[:], pkt[16:20])
		dst = netip.AddrFrom4(b)
	case 6:
		if len(pkt) < 40 {
			return nil
		}
		var b [16]byte
		copy(b[:], pkt[24:40])
		dst = netip.AddrFrom16(b)
	default:
		return nil
	}

	target, ok := v.routingMap.LookupByIP(dst)
	if !ok {
		return nil
	}

	switch target.Kind {
	case RouteTargetClient:
		v.mu.RLock()
		cp := v.clientsBySessionID[target.SessionID]
		v.mu.RUnlock()
		if cp == nil || cp.closed.Load() || cp == src {
			return nil
		}
		return writeSealedTo(cp, pkt)

	case RouteTargetOperator:
		if v.peers == nil {
			return nil
		}
		peer, ok := v.peers.Get(target.OpUUID)
		if !ok {
			return nil
		}
		// Ship the plaintext IP packet to the target PE over the underlay; it
		// re-seals for its local client. Buffer rented from the pool.
		m := message.New()
		if err := m.Seal(v.vni, target.SessionID, pkt); err != nil {
			m.Release()
			return err
		}
		err := peer.WritePacket(*m.Buffer)
		m.Release()
		return err
	}
	return nil
}

// writeSealedTo seals plaintext under cp's data-plane session and writes it.
// cp.session is the session the client handshook with on this PE. A client that
// hopped in from another PE is served by the shared-socket path (PRD §6.4), not
// this per-conn write.
func writeSealedTo(cp *PeerClient, pkt []byte) error {
	if cp.session == nil {
		return nil
	}
	frame, err := dataframe.Seal(cp.session, dataframe.TagOf(cp.sc.SessionID), pkt)
	if err != nil {
		return err
	}
	return cp.Conn.WritePacket(frame)
}

// deliverFromPeer is called when this operator receives a
// MessageTransport from a peer operator's underlay. It only routes to
// local clients — RouteTargetOperator targets are dropped to avoid
// forwarding loops.
func (v *vniEntry) deliverFromPeer(payload []byte) error {
	// Re-resolve dst IP just like forwardFrame does, but skip the
	// keepalive shortcut and the operator-hop branch.
	if len(payload) < 1 {
		return nil
	}
	var dst netip.Addr
	switch payload[0] >> 4 {
	case 4:
		if len(payload) < 20 {
			return nil
		}
		var b [4]byte
		copy(b[:], payload[16:20])
		dst = netip.AddrFrom4(b)
	case 6:
		if len(payload) < 40 {
			return nil
		}
		var b [16]byte
		copy(b[:], payload[24:40])
		dst = netip.AddrFrom16(b)
	default:
		return nil
	}

	target, ok := v.routingMap.LookupByIP(dst)
	if !ok || target.Kind != RouteTargetClient {
		return nil
	}
	v.mu.RLock()
	cp := v.clientsBySessionID[target.SessionID]
	v.mu.RUnlock()
	if cp == nil || cp.closed.Load() {
		return nil
	}
	// payload is a plaintext IP packet off the underlay; re-seal for the local
	// client under its session.
	return writeSealedTo(cp, payload)
}

// buildKeepaliveReply mirrors the client's keepalive shape: a 20-byte
// IP-header-sized buffer with version 3.
func buildKeepaliveReply() []byte {
	pkt := make([]byte, 20)
	pkt[0] = 0x30
	return pkt
}
