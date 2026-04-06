package udp

import (
	"bytes"
	"fmt"
	"net"
	"sync"

	"github.com/jabberwocky238/gasoline/protocol"
)

// Conn wraps a UDP connection with AEAD encryption.
// Each datagram = one encrypted packet, no framing needed.
//
// Client side: wraps a connected *net.UDPConn (via DialUDP).
// Server side: virtual conn muxed from a shared UDP socket.
type Conn struct {
	rawConn    *net.UDPConn
	remoteAddr *net.UDPAddr
	keypair    *protocol.SessionKeypair

	// virtual conn fields (server side)
	incoming  chan []byte
	isVirtual bool
	closed    bool

	readMu  sync.Mutex
	writeMu sync.Mutex
}

func newClientConn(rawConn *net.UDPConn, keypair *protocol.SessionKeypair) *Conn {
	return &Conn{
		rawConn:    rawConn,
		remoteAddr: rawConn.RemoteAddr().(*net.UDPAddr),
		keypair:    keypair,
	}
}

func newVirtualConn(rawConn *net.UDPConn, remoteAddr *net.UDPAddr, keypair *protocol.SessionKeypair) *Conn {
	return &Conn{
		rawConn:    rawConn,
		remoteAddr: remoteAddr,
		keypair:    keypair,
		incoming:   make(chan []byte, 64),
		isVirtual:  true,
	}
}

// WritePacket encrypts and sends one IP packet as a single UDP datagram.
func (c *Conn) WritePacket(data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	encrypted := c.keypair.Send.Seal(data)
	if c.isVirtual {
		_, err := c.rawConn.WriteToUDP(encrypted, c.remoteAddr)
		return err
	}
	_, err := c.rawConn.Write(encrypted)
	return err
}

// ReadPacket receives one UDP datagram, decrypts it, and returns the plaintext IP packet.
func (c *Conn) ReadPacket() ([]byte, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	var datagram []byte
	if c.isVirtual {
		d, ok := <-c.incoming
		if !ok {
			return nil, fmt.Errorf("connection closed")
		}
		datagram = d
	} else {
		buf := make([]byte, 65535)
		n, err := c.rawConn.Read(buf)
		if err != nil {
			return nil, err
		}
		datagram = buf[:n]
	}

	return c.keypair.Receive.Open(datagram)
}

func (c *Conn) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	if c.isVirtual {
		close(c.incoming)
		return nil
	}
	return c.rawConn.Close()
}

func (c *Conn) RemoteAddr() string {
	return c.remoteAddr.String()
}

// deliver routes a datagram into this virtual conn (called by listener muxer).
func (c *Conn) deliver(data []byte) {
	if c.closed {
		return
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	select {
	case c.incoming <- cp:
	default:
	}
}

// --------------- Stream adapter for handshake phase ---------------

// streamAdapter provides io.ReadWriter over UDP datagrams
// so that the handshake protocol (which uses io.ReadFull) works over UDP.
type streamAdapter struct {
	readDatagram  func() ([]byte, error)
	writeDatagram func([]byte) error
	buf           bytes.Buffer
}

func (a *streamAdapter) Read(p []byte) (int, error) {
	if a.buf.Len() > 0 {
		return a.buf.Read(p)
	}
	data, err := a.readDatagram()
	if err != nil {
		return 0, err
	}
	a.buf.Write(data)
	return a.buf.Read(p)
}

func (a *streamAdapter) Write(p []byte) (int, error) {
	return len(p), a.writeDatagram(p)
}

// newClientStreamAdapter wraps a connected UDPConn for handshake.
func newClientStreamAdapter(raw *net.UDPConn) *streamAdapter {
	return &streamAdapter{
		readDatagram: func() ([]byte, error) {
			buf := make([]byte, 65535)
			n, err := raw.Read(buf)
			if err != nil {
				return nil, err
			}
			return buf[:n], nil
		},
		writeDatagram: func(p []byte) error {
			_, err := raw.Write(p)
			return err
		},
	}
}

// newVirtualStreamAdapter wraps a virtual conn's incoming channel for handshake.
func newVirtualStreamAdapter(rawConn *net.UDPConn, remoteAddr *net.UDPAddr, incoming chan []byte) *streamAdapter {
	return &streamAdapter{
		readDatagram: func() ([]byte, error) {
			data, ok := <-incoming
			if !ok {
				return nil, fmt.Errorf("connection closed")
			}
			return data, nil
		},
		writeDatagram: func(p []byte) error {
			_, err := rawConn.WriteToUDP(p, remoteAddr)
			return err
		},
	}
}
