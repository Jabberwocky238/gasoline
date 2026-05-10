package tcp

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Conn wraps a TCP net.Conn with length-prefix framing.
//
// Wire format per packet:
//
//	[frameLen:2 LE][plaintext]
type Conn struct {
	raw net.Conn

	readMu     sync.Mutex
	writeMu    sync.Mutex
	writeBuf   []byte // reused header+payload buffer
	lastActive atomic.Int64 // UnixNano
}

func newConn(raw net.Conn) *Conn {
	// Disable Nagle so each WritePacket goes out immediately. Without
	// this, the two-byte header and the payload (when they end up in
	// separate writes) can sit waiting for an ACK before the next
	// segment leaves, devastating per-packet throughput on loopback.
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	c := &Conn{raw: raw}
	c.lastActive.Store(time.Now().UnixNano())
	return c
}

// WritePacket writes one packet as a framed message in a single Write,
// avoiding the header/data syscall pair.
func (c *Conn) WritePacket(data []byte) error {
	if len(data) > 0xFFFF {
		return fmt.Errorf("tcp: packet too large (%d > 65535)", len(data))
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	need := 2 + len(data)
	if cap(c.writeBuf) < need {
		c.writeBuf = make([]byte, need)
	} else {
		c.writeBuf = c.writeBuf[:need]
	}
	binary.LittleEndian.PutUint16(c.writeBuf[:2], uint16(len(data)))
	copy(c.writeBuf[2:], data)

	if _, err := c.raw.Write(c.writeBuf); err != nil {
		return err
	}
	c.lastActive.Store(time.Now().UnixNano())
	return nil
}

// ReadPacket reads one framed message directly into buf, returning
// the number of bytes copied.
func (c *Conn) ReadPacket(buf []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	var header [2]byte
	if _, err := io.ReadFull(c.raw, header[:]); err != nil {
		return 0, err
	}
	frameLen := int(binary.LittleEndian.Uint16(header[:]))
	if frameLen > len(buf) {
		// Drain the oversized frame so the stream stays in sync.
		discard := make([]byte, frameLen)
		_, _ = io.ReadFull(c.raw, discard)
		return 0, fmt.Errorf("tcp: frame %d > buf %d", frameLen, len(buf))
	}
	if _, err := io.ReadFull(c.raw, buf[:frameLen]); err != nil {
		return 0, err
	}
	c.lastActive.Store(time.Now().UnixNano())
	return frameLen, nil
}

func (c *Conn) Close() error       { return c.raw.Close() }
func (c *Conn) RemoteAddr() string { return c.raw.RemoteAddr().String() }
func (c *Conn) LastActive() time.Time {
	return time.Unix(0, c.lastActive.Load())
}
