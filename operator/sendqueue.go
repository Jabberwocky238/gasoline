package operator

import (
	"net"

	"github.com/jabberwocky238/gasoline/common"
)

// sendItem is a single outbound UDP datagram queued for transmission.
type sendItem struct {
	addr *net.UDPAddr
	data []byte   // wire bytes (slice of poolBuf)
	pool *[]byte  // pooled buffer to return after send, nil if not pooled
}

// sendQueue is a buffered channel-based send queue with a dedicated
// writer goroutine that drains items and writes to the UDP socket.
type sendQueue struct {
	ch   chan sendItem
	conn *net.UDPConn
	done chan struct{}
}

func newSendQueue(conn *net.UDPConn, size int) *sendQueue {
	return &sendQueue{
		ch:   make(chan sendItem, size),
		conn: conn,
		done: make(chan struct{}),
	}
}

// Enqueue adds a datagram to the send queue. Non-blocking: drops if full.
// poolBuf is returned to the pool after the send completes (can be nil).
func (q *sendQueue) Enqueue(addr *net.UDPAddr, data []byte, poolBuf *[]byte) bool {
	select {
	case q.ch <- sendItem{addr: addr, data: data, pool: poolBuf}:
		return true
	default:
		return false
	}
}

// Run drains the queue and writes to the UDP socket. Exits when the channel is closed.
func (q *sendQueue) Run() {
	defer close(q.done)
	for item := range q.ch {
		q.conn.WriteToUDP(item.data, item.addr)
		if item.pool != nil {
			common.PutBuffer(item.pool)
		}
	}
}

// Close shuts down the send queue and waits for the writer to finish.
func (q *sendQueue) Close() {
	close(q.ch)
	<-q.done
}
