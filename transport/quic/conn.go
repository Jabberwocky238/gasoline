package quic

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

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

	// tlsConf, when non-nil, makes this a hopping-capable CLIENT conn: SetHopDest
	// dials a fresh QUIC connection to the new target and swaps the stream (PRD
	// §5.4.4 — QUIC hops by re-connecting, since a connection binds one peer).
	tlsConf *tls.Config
	qconn   *quic.Conn // current underlying connection (client hopping only)
}

func newConn(stream Stream, remoteAddr string) *Conn {
	c := &Conn{stream: stream, remoteAddr: remoteAddr}
	c.lastActive.Store(time.Now().UnixNano())
	return c
}

// newHoppingClientConn wraps a client stream whose destination can hop by
// re-dialing a fresh QUIC connection. qconn/tlsConf are retained so SetHopDest
// can dial anew.
func newHoppingClientConn(stream Stream, qconn *quic.Conn, tlsConf *tls.Config) *Conn {
	c := &Conn{stream: stream, remoteAddr: qconn.RemoteAddr().String(), tlsConf: tlsConf, qconn: qconn}
	c.lastActive.Store(time.Now().UnixNano())
	return c
}

// SetHopDest dials a fresh QUIC connection to dst, opens a stream, and switches
// this conn to it (PRD §5.4.4). The old connection is closed. Satisfies
// transport.HoppingConn. Only valid on a hopping client conn.
func (c *Conn) SetHopDest(dst string) error {
	if c.tlsConf == nil {
		return errNotHopping
	}
	qc, err := quic.DialAddr(context.Background(), dst, c.tlsConf, nil)
	if err != nil {
		return err
	}
	stream, err := qc.OpenStreamSync(context.Background())
	if err != nil {
		qc.CloseWithError(0, "hop stream open failed")
		return err
	}
	c.writeMu.Lock()
	c.readMu.Lock()
	old := c.qconn
	c.stream = stream
	c.qconn = qc
	c.remoteAddr = qc.RemoteAddr().String()
	c.readMu.Unlock()
	c.writeMu.Unlock()
	if old != nil {
		old.CloseWithError(0, "hopped away")
	}
	return nil
}

var errNotHopping = errQUIC("quic: conn is not hopping-capable")

type errQUIC string

func (e errQUIC) Error() string { return string(e) }

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

func (c *Conn) Close() error       { return c.stream.Close() }
func (c *Conn) RemoteAddr() string { return c.remoteAddr }
func (c *Conn) LastActive() time.Time {
	return time.Unix(0, c.lastActive.Load())
}
