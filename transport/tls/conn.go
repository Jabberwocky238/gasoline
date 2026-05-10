package tls

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Conn wraps a TLS net.Conn with length-prefix framing.
//
// Wire format per packet:
//
//	[frameLen:2 LE][plaintext]
//
// Confidentiality is provided by the underlying TLS channel.
type Conn struct {
	raw *tls.Conn

	readMu     sync.Mutex
	writeMu    sync.Mutex
	writeBuf   []byte // reused header+payload buffer
	lastActive atomic.Int64 // UnixNano
}

func newConn(raw *tls.Conn) *Conn {
	// Disable Nagle on the underlying TCP socket; otherwise small TLS
	// records (the framed header + payload pair) can stall waiting on
	// an ACK before the next packet leaves.
	if tc, ok := raw.NetConn().(*net.TCPConn); ok {
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
		return fmt.Errorf("tls: packet too large (%d > 65535)", len(data))
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

// ReadPacket reads one framed message directly into buf.
func (c *Conn) ReadPacket(buf []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	var header [2]byte
	if _, err := io.ReadFull(c.raw, header[:]); err != nil {
		return 0, err
	}
	frameLen := int(binary.LittleEndian.Uint16(header[:]))
	if frameLen > len(buf) {
		discard := make([]byte, frameLen)
		_, _ = io.ReadFull(c.raw, discard)
		return 0, fmt.Errorf("tls: frame %d > buf %d", frameLen, len(buf))
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
