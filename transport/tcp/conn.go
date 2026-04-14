package tcp

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol/encryption"
)

// Conn wraps a TCP net.Conn with length-prefix framing + AEAD encryption.
//
// Wire format per packet:
//
//	[frameLen:2][counter:8][ciphertext + poly1305_tag]
//
// frameLen = AEADHeaderSize + len(plaintext) + AEADTagSize
type Conn struct {
	raw     net.Conn
	keypair *encryption.SessionKeypair

	readMu     sync.Mutex
	writeMu    sync.Mutex
	lastActive atomic.Int64 // UnixNano
}

func newConn(raw net.Conn, keypair *encryption.SessionKeypair) *Conn {
	c := &Conn{raw: raw, keypair: keypair}
	c.lastActive.Store(time.Now().UnixNano())
	return c
}

// WritePacket encrypts one IP packet and writes it as a framed message.
func (c *Conn) WritePacket(data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	tmp := common.GetBuffer()
	encrypted := c.keypair.Send.Seal(*tmp, data)
	defer common.PutBuffer(tmp)

	var header [2]byte
	binary.LittleEndian.PutUint16(header[:], uint16(len(encrypted)))
	if _, err := c.raw.Write(header[:]); err != nil {
		return err
	}
	_, err := c.raw.Write(encrypted)
	if err == nil {
		c.lastActive.Store(time.Now().UnixNano())
	}
	return err
}

// ReadPacket reads one framed message, decrypts it, and copies the plaintext into buf.
// Returns the number of plaintext bytes copied.
func (c *Conn) ReadPacket(buf []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	// Read frame length
	var header [2]byte
	if _, err := io.ReadFull(c.raw, header[:]); err != nil {
		return 0, err
	}
	frameLen := int(binary.LittleEndian.Uint16(header[:]))

	// Read encrypted payload into pooled buffer
	tmp := common.GetBuffer()
	encrypted := (*tmp)[:frameLen]
	if _, err := io.ReadFull(c.raw, encrypted); err != nil {
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

func (c *Conn) Close() error      { return c.raw.Close() }
func (c *Conn) RemoteAddr() string { return c.raw.RemoteAddr().String() }
func (c *Conn) LastActive() time.Time {
	return time.Unix(0, c.lastActive.Load())
}
