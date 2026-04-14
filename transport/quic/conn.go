package quic

import (
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol/encryption"
)

// Stream is the interface that QUIC streams must satisfy.
// This matches quic-go's quic.Stream.
type Stream interface {
	io.ReadWriteCloser
}

// Conn wraps a QUIC stream with length-prefix framing + AEAD encryption.
// Wire format is identical to TCP: [frameLen:2][counter:8][ciphertext + tag]
type Conn struct {
	stream     Stream
	keypair    *encryption.SessionKeypair
	remoteAddr string

	readMu     sync.Mutex
	writeMu    sync.Mutex
	lastActive atomic.Int64 // UnixNano
}

func newConn(stream Stream, keypair *encryption.SessionKeypair, remoteAddr string) *Conn {
	c := &Conn{stream: stream, keypair: keypair, remoteAddr: remoteAddr}
	c.lastActive.Store(time.Now().UnixNano())
	return c
}

func (c *Conn) WritePacket(data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	tmp := common.GetBuffer()
	encrypted := c.keypair.Send.Seal(*tmp, data)
	defer common.PutBuffer(tmp)

	var header [2]byte
	binary.LittleEndian.PutUint16(header[:], uint16(len(encrypted)))
	if _, err := c.stream.Write(header[:]); err != nil {
		return err
	}
	_, err := c.stream.Write(encrypted)
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
	encrypted := (*tmp)[:frameLen]
	if _, err := io.ReadFull(c.stream, encrypted); err != nil {
		common.PutBuffer(tmp)
		return 0, err
	}

	plain, err := c.keypair.Receive.Open(buf, encrypted)
	common.PutBuffer(tmp)
	if err != nil {
		return 0, err
	}
	c.lastActive.Store(time.Now().UnixNano())
	return len(plain), nil
}

func (c *Conn) Close() error      { return c.stream.Close() }
func (c *Conn) RemoteAddr() string { return c.remoteAddr }
func (c *Conn) LastActive() time.Time {
	return time.Unix(0, c.lastActive.Load())
}
