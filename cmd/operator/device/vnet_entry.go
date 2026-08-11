package operator

import (
	"net/netip"
	"sync"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/protocol/message"
)

// vniEntry holds per-VNI runtime state: the active client set, an
// O(1) CID index over those clients, the routing table, and the auth
// strategy.
type vniEntry struct {
	mu            sync.RWMutex
	authenticator auth.ServerAuthenticator

	clients      map[uint32]*PeerClient          // keyed by SessionIndex
	clientsByCID map[protocol.CID_Ty]*PeerClient // hot-path index for forwardFrame

	routingMap *vnetRoutingMap

	// peers is the operator's peer table; forwardFrame consults it when
	// LookupByIP returns a RouteTargetOperator. Set by the owning
	// operatorState at registration time.
	peers *PeerTable
	vni   protocol.VNI_Ty
}

func newVniEntry(authn auth.ServerAuthenticator) *vniEntry {
	return &vniEntry{
		authenticator: authn,
		clients:       make(map[uint32]*PeerClient),
		clientsByCID:  make(map[protocol.CID_Ty]*PeerClient),
		routingMap:    newVnetRoutingMap(),
	}
}

func (v *vniEntry) addClient(cp *PeerClient) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.clients[cp.sc.SessionIndex] = cp
	v.clientsByCID[cp.sc.CID] = cp
}

func (v *vniEntry) removeClient(sessionIndex uint32) {
	v.mu.Lock()
	defer v.mu.Unlock()
	cp, ok := v.clients[sessionIndex]
	if !ok {
		return
	}
	delete(v.clients, sessionIndex)
	// Only drop the CID index entry if it still points at *this* client;
	// a CID re-bound to a fresh session must not be cleared by an old
	// session's teardown.
	if cur, ok := v.clientsByCID[cp.sc.CID]; ok && cur == cp {
		delete(v.clientsByCID, cp.sc.CID)
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

// forwardFrame routes one IP packet read from src.
//
//   - Version 3 (keepalive): reflect a v3 packet back to src and stop.
//   - Version 4/6: LPM dst → RouteTarget.
//   - RouteTargetClient: O(1) CID lookup, write raw IP to that client.
//   - RouteTargetOperator: wrap as MessageTransport(vni, dst-cid, ip)
//     and ship to the peer's UDP underlay.
//   - Other versions: silently drop.
//
// The hot path (Client target) avoids any allocation: the same buffer
// the read loop owns is forwarded straight to the destination conn.
func (v *vniEntry) forwardFrame(frame []byte, src *PeerClient) error {
	if len(frame) < 1 {
		return nil
	}
	version := frame[0] >> 4

	var dst netip.Addr
	switch version {
	case 3:
		if src == nil || src.closed.Load() {
			return nil
		}
		return src.Conn.WritePacket(buildKeepaliveReply())
	case 4:
		if len(frame) < 20 {
			return nil
		}
		var b [4]byte
		copy(b[:], frame[16:20])
		dst = netip.AddrFrom4(b)
	case 6:
		if len(frame) < 40 {
			return nil
		}
		var b [16]byte
		copy(b[:], frame[24:40])
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
		cp := v.clientsByCID[target.CID]
		v.mu.RUnlock()
		if cp == nil || cp.closed.Load() || cp == src {
			return nil
		}
		return cp.Conn.WritePacket(frame)

	case RouteTargetOperator:
		if v.peers == nil {
			return nil
		}
		peer, ok := v.peers.Get(target.OpUUID)
		if !ok {
			return nil
		}
		// Wrap and ship. Buffer is rented from the pool, returned on
		// the way out.
		m := message.New()
		if err := m.Seal(v.vni, target.CID, frame); err != nil {
			m.Release()
			return err
		}
		err := peer.WritePacket(*m.Buffer)
		m.Release()
		return err
	}
	return nil
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
	cp := v.clientsByCID[target.CID]
	v.mu.RUnlock()
	if cp == nil || cp.closed.Load() {
		return nil
	}
	return cp.Conn.WritePacket(payload)
}

// buildKeepaliveReply mirrors the client's keepalive shape: a 20-byte
// IP-header-sized buffer with version 3.
func buildKeepaliveReply() []byte {
	pkt := make([]byte, 20)
	pkt[0] = 0x30
	return pkt
}
