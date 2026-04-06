package quic

import (
	"encoding/binary"
	"io"
	"sync"

	"github.com/jabberwocky238/gasoline/protocol"
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
	keypair    *protocol.SessionKeypair
	remoteAddr string

	readMu  sync.Mutex
	writeMu sync.Mutex
}

func newConn(stream Stream, keypair *protocol.SessionKeypair, remoteAddr string) *Conn {
	return &Conn{stream: stream, keypair: keypair, remoteAddr: remoteAddr}
}

func (c *Conn) WritePacket(data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	encrypted := c.keypair.Send.Seal(data)

	var header [2]byte
	binary.LittleEndian.PutUint16(header[:], uint16(len(encrypted)))
	if _, err := c.stream.Write(header[:]); err != nil {
		return err
	}
	_, err := c.stream.Write(encrypted)
	return err
}

func (c *Conn) ReadPacket() ([]byte, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	var header [2]byte
	if _, err := io.ReadFull(c.stream, header[:]); err != nil {
		return nil, err
	}
	frameLen := int(binary.LittleEndian.Uint16(header[:]))

	encrypted := make([]byte, frameLen)
	if _, err := io.ReadFull(c.stream, encrypted); err != nil {
		return nil, err
	}

	return c.keypair.Receive.Open(encrypted)
}

func (c *Conn) Close() error      { return c.stream.Close() }
func (c *Conn) RemoteAddr() string { return c.remoteAddr }
