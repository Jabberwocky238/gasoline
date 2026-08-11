package udp

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jabberwocky238/gasoline/common"
)

// pooledDatagram carries a datagram backed by a pool buffer.
// The receiver must call release() after processing.
type pooledDatagram struct {
	data []byte  // sub-slice of *buf
	buf  *[]byte // pool buffer to return
}

func (d *pooledDatagram) release() {
	if d.buf != nil {
		common.PutBuffer(d.buf)
		d.buf = nil
	}
}

// Conn wraps a UDP connection. Each datagram = one packet, no framing needed.
//
// Client side: wraps a connected *net.UDPConn (via DialUDP).
// Server side: virtual conn muxed from a shared UDP socket.
type Conn struct {
	rawConn    *net.UDPConn
	remoteAddr *net.UDPAddr

	// hopTarget, when non-nil, makes this an unconnected client socket whose
	// send destination can change at runtime (PRD §5/§6: client hopping). The
	// tx path reads it per packet via WriteToUDP; SetHopTarget swaps it. When
	// nil the conn is a plain connected socket (server-side virtual conns and
	// non-hopping clients).
	hopTarget atomic.Pointer[net.UDPAddr]

	// virtual conn fields (server side)
	incoming  chan pooledDatagram
	isVirtual bool
	closed    atomic.Bool

	readMu     sync.Mutex
	lastActive atomic.Int64 // UnixNano
}

func newClientConn(rawConn *net.UDPConn) *Conn {
	c := &Conn{
		rawConn:    rawConn,
		remoteAddr: rawConn.RemoteAddr().(*net.UDPAddr),
	}
	c.lastActive.Store(time.Now().UnixNano())
	return c
}

// newHoppingClientConn wraps an UNCONNECTED client socket whose send target
// starts at boot and can be changed with SetHopTarget. Reads accept datagrams
// from any source (a hopped reply comes back from whichever server IP/port the
// operator used).
func newHoppingClientConn(rawConn *net.UDPConn, boot *net.UDPAddr) *Conn {
	c := &Conn{rawConn: rawConn, remoteAddr: boot}
	c.hopTarget.Store(boot)
	c.lastActive.Store(time.Now().UnixNano())
	return c
}

// SetHopTarget changes the destination subsequent writes go to. Safe to call
// concurrently with WritePacket.
func (c *Conn) SetHopTarget(dst *net.UDPAddr) { c.hopTarget.Store(dst) }

// SetHopDest resolves dst ("host:port") and points subsequent writes at it,
// satisfying transport.HoppingConn. Only valid on a hopping client conn (one
// created with newHoppingClientConn); a no-op target on a connected conn would
// be silently ignored by WritePacket, so guard against misuse.
func (c *Conn) SetHopDest(dst string) error {
	if c.hopTarget.Load() == nil {
		return fmt.Errorf("udp: conn is not hopping-capable")
	}
	addr, err := net.ResolveUDPAddr("udp", dst)
	if err != nil {
		return err
	}
	c.hopTarget.Store(addr)
	return nil
}

func newVirtualConn(rawConn *net.UDPConn, remoteAddr *net.UDPAddr) *Conn {
	c := &Conn{
		rawConn:    rawConn,
		remoteAddr: remoteAddr,
		incoming:   make(chan pooledDatagram, peerIncomingCap),
		isVirtual:  true,
	}
	c.lastActive.Store(time.Now().UnixNano())
	return c
}

// WritePacket sends one IP packet as a single UDP datagram.
func (c *Conn) WritePacket(data []byte) error {
	var err error
	switch {
	case c.isVirtual:
		_, err = c.rawConn.WriteToUDP(data, c.remoteAddr)
	case c.hopTarget.Load() != nil:
		// Unconnected hopping socket: send to the current hop target.
		_, err = c.rawConn.WriteToUDP(data, c.hopTarget.Load())
	default:
		_, err = c.rawConn.Write(data)
	}
	if err == nil {
		c.lastActive.Store(time.Now().UnixNano())
	}
	return err
}

// ReadPacket receives one UDP datagram and copies the payload into buf.
// Returns the number of bytes copied.
func (c *Conn) ReadPacket(buf []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if c.isVirtual {
		dg, ok := <-c.incoming
		if !ok {
			return 0, fmt.Errorf("connection closed")
		}
		n := copy(buf, dg.data)
		dg.release()
		c.lastActive.Store(time.Now().UnixNano())
		return n, nil
	}

	n, err := c.rawConn.Read(buf)
	if err != nil {
		return 0, err
	}
	c.lastActive.Store(time.Now().UnixNano())
	return n, nil
}

func (c *Conn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	if c.isVirtual {
		close(c.incoming)
		return nil
	}
	return c.rawConn.Close()
}

func (c *Conn) RemoteAddr() string {
	return c.remoteAddr.String()
}

func (c *Conn) LastActive() time.Time {
	return time.Unix(0, c.lastActive.Load())
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

// newClientStreamAdapterTo wraps an UNCONNECTED UDPConn for handshake, sending
// to dst and accepting replies from any source. Used by the hopping client,
// whose socket must stay unconnected so the data plane can change destination.
func newClientStreamAdapterTo(raw *net.UDPConn, dst *net.UDPAddr) *streamAdapter {
	return &streamAdapter{
		readDatagram: func() ([]byte, error) {
			buf := make([]byte, 65535)
			n, _, err := raw.ReadFromUDP(buf)
			if err != nil {
				return nil, err
			}
			return buf[:n], nil
		},
		writeDatagram: func(p []byte) error {
			_, err := raw.WriteToUDP(p, dst)
			return err
		},
	}
}

// newVirtualStreamAdapter wraps a virtual conn's incoming channel for handshake.
// During handshake, pool buffers are released immediately after reading.
func newVirtualStreamAdapter(rawConn *net.UDPConn, remoteAddr *net.UDPAddr, incoming chan pooledDatagram) *streamAdapter {
	return &streamAdapter{
		readDatagram: func() ([]byte, error) {
			dg, ok := <-incoming
			if !ok {
				return nil, fmt.Errorf("connection closed")
			}
			// Copy out during handshake (small messages), release pool buffer immediately
			data := make([]byte, len(dg.data))
			copy(data, dg.data)
			dg.release()
			return data, nil
		},
		writeDatagram: func(p []byte) error {
			_, err := rawConn.WriteToUDP(p, remoteAddr)
			return err
		},
	}
}
