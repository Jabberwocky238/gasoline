package operator

import (
	"fmt"
	"net"
	"sync"
)

// PeerTable indexes peer operators by UUID and owns the shared
// underlay UDP socket every peer sends through.
type PeerTable struct {
	mu    sync.RWMutex
	peers map[[16]byte]*PeerOperator
	conn  *net.UDPConn
}

func NewPeerTable() *PeerTable {
	return &PeerTable{peers: make(map[[16]byte]*PeerOperator)}
}

// Bind binds the underlay UDP socket on addr and stamps it onto every
// peer already in the table. Subsequent Add calls also pick it up.
func (t *PeerTable) Bind(addr string) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("peer-table resolve %s: %w", addr, err)
	}
	c, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("peer-table listen %s: %w", addr, err)
	}
	t.mu.Lock()
	t.conn = c
	for _, p := range t.peers {
		p.SetSendSocket(c)
	}
	t.mu.Unlock()
	return c, nil
}

// Conn returns the bound underlay socket, or nil before Bind.
func (t *PeerTable) Conn() *net.UDPConn {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.conn
}

// Addr returns the bound underlay socket's local address ("host:port"),
// or "" before Bind.
func (t *PeerTable) Addr() string {
	c := t.Conn()
	if c == nil {
		return ""
	}
	return c.LocalAddr().String()
}

// Close shuts the underlay socket and clears it from peers.
func (t *PeerTable) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, p := range t.peers {
		p.SetSendSocket(nil)
	}
	if t.conn == nil {
		return nil
	}
	err := t.conn.Close()
	t.conn = nil
	return err
}

func (t *PeerTable) Add(p *PeerOperator) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn != nil {
		p.SetSendSocket(t.conn)
	}
	t.peers[p.UUID] = p
}

func (t *PeerTable) Remove(uuid [16]byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.peers, uuid)
}

func (t *PeerTable) Get(uuid [16]byte) (*PeerOperator, bool) {
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

func (t *PeerTable) All() []*PeerOperator {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]*PeerOperator, 0, len(t.peers))
	for _, p := range t.peers {
		out = append(out, p)
	}
	return out
}
