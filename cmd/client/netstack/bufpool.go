package netstack

import "sync"

// proxyBufSize is the size of each buffer handed out by getProxyBuf. Sized
// just over the IPv4 max UDP payload (65507) so any single datagram fits,
// with slack the TCP splice path also benefits from (io.CopyBuffer uses the
// buffer when neither end implements WriterTo/ReaderFrom — gonet.TCPConn
// does not).
const proxyBufSize = 64*1024 + 64

var proxyBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, proxyBufSize)
		return &b
	},
}

// getProxyBuf returns a full-length proxyBufSize buffer from the pool. The
// returned buffer MUST be released via putProxyBuf by the same goroutine
// (or at least after every concurrent user has stopped reading from it) —
// see the safety note in dialer.go about socks5UDPPacketConn.rdBuf for why
// pooling isn't applied there.
//
// Buffers come back at their original length; callers slice as needed.
func getProxyBuf() *[]byte {
	return proxyBufPool.Get().(*[]byte)
}

// putProxyBuf returns a buffer to the pool. Resets the slice length back to
// cap so a caller that did `*b = (*b)[:n]` doesn't shorten the pooled view.
func putProxyBuf(b *[]byte) {
	*b = (*b)[:cap(*b)]
	proxyBufPool.Put(b)
}
