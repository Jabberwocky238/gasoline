package common

import "sync"

const MaxPacketSize = 2048

// WaitPool is a bounded pool with backpressure.
// When the pool is exhausted, Get blocks until a buffer is returned via Put.
// Inspired by WireGuard-Go's WaitPool design.
type WaitPool struct {
	pool  sync.Pool
	cond  sync.Cond
	lock  sync.Mutex
	count uint32
	max   uint32
}

func NewWaitPool(max uint32, newFn func() any) *WaitPool {
	p := &WaitPool{pool: sync.Pool{New: newFn}, max: max}
	p.cond = sync.Cond{L: &p.lock}
	return p
}

func (p *WaitPool) Get() any {
	if p.max != 0 {
		p.lock.Lock()
		for p.count >= p.max {
			p.cond.Wait()
		}
		p.count++
		p.lock.Unlock()
	}
	return p.pool.Get()
}

func (p *WaitPool) Put(x any) {
	p.pool.Put(x)
	if p.max == 0 {
		return
	}
	p.lock.Lock()
	defer p.lock.Unlock()
	p.count--
	p.cond.Signal()
}

// --------------- Byte-buffer pool ---------------

// DefaultBufferPool is the global packet buffer pool.
// max=0 means unbounded (same as sync.Pool), set via InitBufferPool for backpressure.
var DefaultBufferPool = NewWaitPool(0, func() any {
	buf := make([]byte, MaxPacketSize)
	return &buf
})

// InitBufferPool re-initializes the global pool with a bounded max.
// Call once at startup before any Get/Put.
func InitBufferPool(max uint32) {
	DefaultBufferPool = NewWaitPool(max, func() any {
		buf := make([]byte, MaxPacketSize)
		return &buf
	})
}

// GetBuffer retrieves a buffer from the pool.
func GetBuffer() *[]byte {
	return DefaultBufferPool.Get().(*[]byte)
}

// PutBuffer returns a buffer to the pool.
func PutBuffer(buf *[]byte) {
	DefaultBufferPool.Put(buf)
}

// --------------- DataFrame pool ---------------

// DefaultFramePool is the global VXLAN DataFrame pool.
// max=0 means unbounded; set via InitFramePool for backpressure.
var DefaultFramePool = NewWaitPool(0, func() any {
	return new(DataFrame)
})

// InitFramePool re-initializes the global frame pool with a bounded max.
// Call once at startup before any GetFrame/PutFrame.
func InitFramePool(max uint32) {
	DefaultFramePool = NewWaitPool(max, func() any {
		return new(DataFrame)
	})
}

// GetFrame retrieves a DataFrame from the global pool.
func GetFrame() *DataFrame {
	return DefaultFramePool.Get().(*DataFrame)
}

// PutFrame returns a DataFrame to the global pool after resetting it.
func PutFrame(f *DataFrame) {
	f.Reset()
	DefaultFramePool.Put(f)
}
