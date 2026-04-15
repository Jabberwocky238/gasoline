package ctrl

import (
	"net"
	"net/netip"
	"sync"

	"google.golang.org/grpc"
)

// Peer represents a remote operator's gRPC client connection.
type Peer struct {
	UUID        [16]byte
	Addr        string          // external address ("host:port")
	UDPAddrPort netip.AddrPort  // cached resolved UDP endpoint for the data plane
	conn        *grpc.ClientConn
	Client      OperatorServiceClient
}

func NewPeer(uuid [16]byte, addr string, conn *grpc.ClientConn) *Peer {
	var ap netip.AddrPort
	if ua, err := net.ResolveUDPAddr("udp", addr); err == nil && ua != nil {
		ap = ua.AddrPort()
	}
	return &Peer{
		UUID:        uuid,
		Addr:        addr,
		UDPAddrPort: ap,
		conn:        conn,
		Client:      NewOperatorServiceClient(conn),
	}
}

func (p *Peer) Close() error {
	return p.conn.Close()
}

// PeerTable manages connections to remote operators indexed by UUID.
type PeerTable struct {
	mu    sync.RWMutex
	peers map[[16]byte]*Peer
}

func NewPeerTable() *PeerTable {
	return &PeerTable{
		peers: make(map[[16]byte]*Peer),
	}
}

func (t *PeerTable) Add(p *Peer) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.peers[p.UUID] = p
}

func (t *PeerTable) Remove(uuid [16]byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.peers, uuid)
}

func (t *PeerTable) Get(uuid [16]byte) (*Peer, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	p, ok := t.peers[uuid]
	return p, ok
}

func (t *PeerTable) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.peers)
}

func (t *PeerTable) All() []*Peer {
	t.mu.RLock()
	defer t.mu.RUnlock()
	peers := make([]*Peer, 0, len(t.peers))
	for _, p := range t.peers {
		peers = append(peers, p)
	}
	return peers
}

func (t *PeerTable) CloseAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, p := range t.peers {
		p.Close()
	}
}
