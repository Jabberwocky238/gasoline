package ctrl

import (
	"net"
	"sync"

	"google.golang.org/grpc"
)

// Peer represents a remote operator's gRPC client connection.
type Peer struct {
	UUID    [16]byte
	Addr    string // external address
	UDPAddr *net.UDPAddr // cached resolved UDP address for data plane
	conn    *grpc.ClientConn
	Client  OperatorServiceClient
}

func NewPeer(uuid [16]byte, addr string, conn *grpc.ClientConn) *Peer {
	udpAddr, _ := net.ResolveUDPAddr("udp", addr)
	return &Peer{
		UUID:    uuid,
		Addr:    addr,
		UDPAddr: udpAddr,
		conn:    conn,
		Client:  NewOperatorServiceClient(conn),
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
