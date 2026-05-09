package quic

import (
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jabberwocky238/gasoline/common"
)

// Stream is the interface that QUIC streams must satisfy.
// This matches quic-go's quic.Stream.
type Stream interface {
	io.ReadWriteCloser
}

// Conn wraps a QUIC stream with length-prefix framing.
// Wire format per packet: [frameLen:2][plaintext]
// (Confidentiality is provided by the underlying QUIC channel.)
type Conn struct {
	stream     Stream
	remoteAddr string

	readMu     sync.Mutex
	writeMu    sync.Mutex
	lastActive atomic.Int64 // UnixNano
}

func newConn(stream Stream, remoteAddr string) *Conn {
	c := &Conn{stream: stream, remoteAddr: remoteAddr}
	c.lastActive.Store(time.Now().UnixNano())
	return c
}

func (c *Conn) WritePacket(data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	var header [2]byte
	binary.LittleEndian.PutUint16(header[:], uint16(len(data)))
	if _, err := c.stream.Write(header[:]); err != nil {
		return err
	}
	_, err := c.stream.Write(data)
	if err == nil {
		c.lastActive.Store(time.Now().UnixNano())
	}
	return err
}

func (c *Conn) ReadPacket(buf []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	var header [2]byte
	if _, err := io.ReadFull(c.stream, header[:]); err != nil {
		return 0, err
	}
	frameLen := int(binary.LittleEndian.Uint16(header[:]))

	tmp := common.GetBuffer()
	payload := (*tmp)[:frameLen]
	if _, err := io.ReadFull(c.stream, payload); err != nil {
		common.PutBuffer(tmp)
		return 0, err
	}
	n := copy(buf, payload)
	common.PutBuffer(tmp)
	c.lastActive.Store(time.Now().UnixNano())
	return n, nil
}

func (c *Conn) Close() error      { return c.stream.Close() }
func (c *Conn) RemoteAddr() string { return c.remoteAddr }
func (c *Conn) LastActive() time.Time {
	return time.Unix(0, c.lastActive.Load())
}
