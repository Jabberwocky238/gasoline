package tcp

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jabberwocky238/gasoline/common"
)

// Conn wraps a TCP net.Conn with length-prefix framing.
//
// Wire format per packet:
//
//	[frameLen:2][plaintext]
type Conn struct {
	raw net.Conn

	readMu     sync.Mutex
	writeMu    sync.Mutex
	lastActive atomic.Int64 // UnixNano
}

func newConn(raw net.Conn) *Conn {
	c := &Conn{raw: raw}
	c.lastActive.Store(time.Now().UnixNano())
	return c
}

// WritePacket writes one IP packet as a framed message.
func (c *Conn) WritePacket(data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	var header [2]byte
	binary.LittleEndian.PutUint16(header[:], uint16(len(data)))
	if _, err := c.raw.Write(header[:]); err != nil {
		return err
	}
	_, err := c.raw.Write(data)
	if err == nil {
		c.lastActive.Store(time.Now().UnixNano())
	}
	return err
}

// ReadPacket reads one framed message and copies the payload into buf.
// Returns the number of bytes copied.
func (c *Conn) ReadPacket(buf []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	var header [2]byte
	if _, err := io.ReadFull(c.raw, header[:]); err != nil {
		return 0, err
	}
	frameLen := int(binary.LittleEndian.Uint16(header[:]))

	tmp := common.GetBuffer()
	payload := (*tmp)[:frameLen]
	if _, err := io.ReadFull(c.raw, payload); err != nil {
		common.PutBuffer(tmp)
		return 0, err
	}
	n := copy(buf, payload)
	common.PutBuffer(tmp)
	c.lastActive.Store(time.Now().UnixNano())
	return n, nil
}

func (c *Conn) Close() error      { return c.raw.Close() }
func (c *Conn) RemoteAddr() string { return c.raw.RemoteAddr().String() }
func (c *Conn) LastActive() time.Time {
	return time.Unix(0, c.lastActive.Load())
}
