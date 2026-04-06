package tcp

import (
	"encoding/binary"
	"io"
	"net"
	"sync"

	"github.com/jabberwocky238/gasoline/protocol"
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
	keypair *protocol.SessionKeypair

	readMu  sync.Mutex
	writeMu sync.Mutex
}

func newConn(raw net.Conn, keypair *protocol.SessionKeypair) *Conn {
	return &Conn{raw: raw, keypair: keypair}
}

// WritePacket encrypts one IP packet and writes it as a framed message.
func (c *Conn) WritePacket(data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	encrypted := c.keypair.Send.Seal(data)

	var header [2]byte
	binary.LittleEndian.PutUint16(header[:], uint16(len(encrypted)))
	if _, err := c.raw.Write(header[:]); err != nil {
		return err
	}
	_, err := c.raw.Write(encrypted)
	return err
}

// ReadPacket reads one framed message, decrypts it, and returns the plaintext IP packet.
func (c *Conn) ReadPacket() ([]byte, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	// Read frame length
	var header [2]byte
	if _, err := io.ReadFull(c.raw, header[:]); err != nil {
		return nil, err
	}
	frameLen := int(binary.LittleEndian.Uint16(header[:]))

	// Read encrypted payload
	encrypted := make([]byte, frameLen)
	if _, err := io.ReadFull(c.raw, encrypted); err != nil {
		return nil, err
	}

	return c.keypair.Receive.Open(encrypted)
}

func (c *Conn) Close() error      { return c.raw.Close() }
func (c *Conn) RemoteAddr() string { return c.raw.RemoteAddr().String() }
