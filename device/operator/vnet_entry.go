package operator

import (
	"net/netip"
	"sync"

	"github.com/jabberwocky238/gasoline/protocol/auth"
)

// vniEntry holds per-VNI runtime state: the active client set, the
// authoritative cid<->prefix routing table, and its auth strategy.
type vniEntry struct {
	mu            sync.RWMutex
	authenticator auth.ServerAuthenticator
	clients       map[uint32]*PeerClient // keyed by SessionIndex
	routingMap    *vnetRoutingMap
}

func newVniEntry(authn auth.ServerAuthenticator) *vniEntry {
	return &vniEntry{
		authenticator: authn,
		clients:       make(map[uint32]*PeerClient),
		routingMap:    newVnetRoutingMap(),
	}
}

func (v *vniEntry) addClient(cp *PeerClient) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.clients[cp.SessionIndex] = cp
}

func (v *vniEntry) removeClient(sessionIndex uint32) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.clients, sessionIndex)
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

// forwardFrame inspects the IP header of frame, looks up the
// destination IP in the routing map (longest-prefix-match), finds the
// owning client by CID, and writes the frame straight to that client.
//
// Special case: IP version 3 means "client keepalive". The operator
// replies with another v3 packet to the same client and stops there —
// nothing is forwarded onto the VNet. Versions other than 3/4/6 are
// silently dropped.
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

	cid, ok := v.routingMap.LookupByIP(dst)
	if !ok {
		return nil
	}

	v.mu.RLock()
	var target *PeerClient
	for _, cp := range v.clients {
		if cp.CID == cid {
			target = cp
			break
		}
	}
	v.mu.RUnlock()

	if target == nil || target.closed.Load() || target == src {
		return nil
	}
	return target.Conn.WritePacket(frame)
}

// buildKeepaliveReply mirrors the client's keepalive shape: a 20-byte
// IP-header-sized buffer with version 3.
func buildKeepaliveReply() []byte {
	pkt := make([]byte, 20)
	pkt[0] = 0x30
	return pkt
}
