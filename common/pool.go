package common

import "sync"

const MaxMTU = 2000

// PacketPool is a sync.Pool for reusable packet buffers.
var PacketPool = sync.Pool{
	New: func() any {
		buf := make([]byte, MaxMTU)
		return &buf
	},
}

// GetBuffer retrieves a buffer from the pool.
func GetBuffer() *[]byte {
	return PacketPool.Get().(*[]byte)
}

// PutBuffer returns a buffer to the pool.
func PutBuffer(buf *[]byte) {
	PacketPool.Put(buf)
}
