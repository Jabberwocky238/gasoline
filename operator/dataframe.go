package operator

import (
	"fmt"
	"sync"
)

// Data frame wire format (one UDP datagram = one frame):
//   [vnetID:16][raw IP packet]

const (
	vnetIDSize      = 16
	maxDatagramSize = 65535
)

// DataFrame is a pooled, reusable data frame buffer.
// Get one via FramePool.Get(), return it with FramePool.Put().
type DataFrame struct {
	buf    [maxDatagramSize]byte // fixed backing array, no alloc
	VNetID [vnetIDSize]byte
	Packet []byte // slice into buf
	Size   int    // total wire size (vnetIDSize + packet len)
}

// Encode writes vnetID + packet into the frame's buffer.
// Returns the wire bytes (a slice of the internal buffer — valid until Put).
func (f *DataFrame) Encode(vnetID [16]byte, packet []byte) []byte {
	f.Size = vnetIDSize + len(packet)
	copy(f.buf[:vnetIDSize], vnetID[:])
	copy(f.buf[vnetIDSize:], packet)
	f.VNetID = vnetID
	f.Packet = f.buf[vnetIDSize:f.Size]
	return f.buf[:f.Size]
}

// Decode parses a received UDP datagram into the frame.
// data is copied into the internal buffer so the caller can reuse their read buffer.
func (f *DataFrame) Decode(data []byte) error {
	if len(data) < vnetIDSize {
		return fmt.Errorf("data frame too short: %d", len(data))
	}
	f.Size = len(data)
	copy(f.buf[:f.Size], data)
	copy(f.VNetID[:], f.buf[:vnetIDSize])
	f.Packet = f.buf[vnetIDSize:f.Size]
	return nil
}

// Reset clears the frame for reuse.
func (f *DataFrame) Reset() {
	f.Packet = nil
	f.Size = 0
}

// FramePool is a bounded pool of DataFrame buffers, inspired by WireGuard's WaitPool.
// When the pool is exhausted, Get blocks until a frame is returned via Put.
type FramePool struct {
	pool  sync.Pool
	cond  sync.Cond
	lock  sync.Mutex
	count uint32
	max   uint32
}

func NewFramePool(max uint32) *FramePool {
	p := &FramePool{
		pool: sync.Pool{New: func() any { return new(DataFrame) }},
		max:  max,
	}
	p.cond = sync.Cond{L: &p.lock}
	return p
}

func (p *FramePool) Get() *DataFrame {
	if p.max != 0 {
		p.lock.Lock()
		for p.count >= p.max {
			p.cond.Wait()
		}
		p.count++
		p.lock.Unlock()
	}
	return p.pool.Get().(*DataFrame)
}

func (p *FramePool) Put(f *DataFrame) {
	f.Reset()
	p.pool.Put(f)
	if p.max == 0 {
		return
	}
	p.lock.Lock()
	defer p.lock.Unlock()
	p.count--
	p.cond.Signal()
}
