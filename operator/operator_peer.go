package operator

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

// OperatorPeer represents a remote operator in the cluster
// and wraps the TCP connection for frame-based communication.
type OperatorPeer struct {
	UUID    OperatorUUIDType
	conn    net.Conn
	readMu  sync.Mutex
	writeMu sync.Mutex
}

func NewOperatorPeer(uuid OperatorUUIDType, conn net.Conn) *OperatorPeer {
	return &OperatorPeer{UUID: uuid, conn: conn}
}

// Send writes a frame to the peer operator.
func (op *OperatorPeer) Send(f *Frame) error {
	op.writeMu.Lock()
	defer op.writeMu.Unlock()
	return WriteFrame(op.conn, f)
}

// Recv reads a frame from the peer operator.
func (op *OperatorPeer) Recv() (*Frame, error) {
	op.readMu.Lock()
	defer op.readMu.Unlock()
	return ReadFrame(op.conn)
}

// SendData sends a data frame with vnet ID and raw packet.
func (op *OperatorPeer) SendData(vnetID [vnetIDSize]byte, packet []byte) error {
	return op.Send(MakeDataFrame(vnetID, packet))
}

// SendControl sends a control frame.
func (op *OperatorPeer) SendControl(subtype ControlSubtype, payload []byte) error {
	return op.Send(MakeControlFrame(subtype, payload))
}

func (op *OperatorPeer) Close() error {
	return op.conn.Close()
}

func (op *OperatorPeer) RemoteAddr() string {
	return op.conn.RemoteAddr().String()
}

// --------------- Ping payload ---------------

func EncodePingPayload(unixNano int64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(unixNano))
	return buf
}

func DecodePingPayload(data []byte) (int64, error) {
	if len(data) < 8 {
		return 0, fmt.Errorf("ping payload too short: %d", len(data))
	}
	return int64(binary.BigEndian.Uint64(data[:8])), nil
}

// --------------- OperatorTable ---------------

// OperatorTable manages connections to remote operators indexed by UUID.
type OperatorTable struct {
	mu    sync.RWMutex
	peers map[OperatorUUIDType]*OperatorPeer
}

func NewOperatorTable() *OperatorTable {
	return &OperatorTable{
		peers: make(map[OperatorUUIDType]*OperatorPeer),
	}
}

func (ot *OperatorTable) Add(op *OperatorPeer) {
	ot.mu.Lock()
	defer ot.mu.Unlock()
	ot.peers[op.UUID] = op
}

func (ot *OperatorTable) Remove(uuid OperatorUUIDType) {
	ot.mu.Lock()
	defer ot.mu.Unlock()
	delete(ot.peers, uuid)
}

func (ot *OperatorTable) Get(uuid OperatorUUIDType) (*OperatorPeer, bool) {
	ot.mu.RLock()
	defer ot.mu.RUnlock()
	op, ok := ot.peers[uuid]
	return op, ok
}

func (ot *OperatorTable) Len() int {
	ot.mu.RLock()
	defer ot.mu.RUnlock()
	return len(ot.peers)
}

// FindByConn returns the OperatorPeer that uses the given net.Conn.
func (ot *OperatorTable) FindByConn(conn net.Conn) *OperatorPeer {
	ot.mu.RLock()
	defer ot.mu.RUnlock()
	for _, op := range ot.peers {
		if op.conn == conn {
			return op
		}
	}
	return nil
}

func (ot *OperatorTable) CloseAll() {
	ot.mu.Lock()
	defer ot.mu.Unlock()
	for _, op := range ot.peers {
		op.Close()
	}
}
