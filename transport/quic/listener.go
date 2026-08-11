package quic

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"

	"github.com/quic-go/quic-go"

	"github.com/jabberwocky238/gasoline/protocol/handshake"
	"github.com/jabberwocky238/gasoline/transport"
)

type Listener struct {
	inner  *quic.Listener
	mapper handshake.VNIMapperFn

	// demux, if set, gets first refusal on a NEW connection whose first stream
	// frame is a data frame for an existing session (a QUIC-hopped client, PRD
	// §5.4.4). It returns true if it consumed the frame stream.
	demux func(remote string, firstFrame []byte, sendFrame func([]byte) error) bool
}

func NewListener(addr string, mapper handshake.VNIMapperFn, tlsConf *tls.Config) (*Listener, error) {
	ln, err := quic.ListenAddr(addr, tlsConf, nil)
	if err != nil {
		return nil, err
	}
	return &Listener{inner: ln, mapper: mapper}, nil
}

// SetDataDemux installs the hopped-connection handler (PRD §5.4.4). Call before
// Accept starts. See transport.QUICHoppableListener.
func (l *Listener) SetDataDemux(d func(remote string, firstFrame []byte, sendFrame func([]byte) error) bool) {
	l.demux = d
}

func (l *Listener) Accept() (transport.Accepted, error) {
	for {
		conn, err := l.inner.Accept(context.Background())
		if err != nil {
			return transport.Accepted{}, err
		}
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			conn.CloseWithError(0, "stream accept failed")
			continue
		}

		// Peek the first framed message. A hopped client sends a data frame
		// first; a fresh client sends a ClientHello. Both are length-prefixed
		// here, so read one frame and decide.
		first, err := readFrame(stream)
		if err != nil {
			conn.CloseWithError(0, "first frame read failed")
			continue
		}

		// Offer to the demux: if it recognizes a data frame for a live session,
		// it serves this connection as a hop and we keep accepting. Replies go
		// back on the same accepted stream.
		if l.demux != nil {
			st := stream // capture
			sender := func(reply []byte) error { return writeStreamFrame(st, reply) }
			if l.demux(conn.RemoteAddr().String(), first, sender) {
				go l.pumpHopped(conn, stream, sender)
				continue
			}
		}

		// Not a hop: replay the first frame into the handshake as a prefixed
		// reader, then run the normal server handshake.
		rw := &prefixedStream{Stream: stream, first: first}
		auth, err := handshake.ServerHandshake(rw, l.mapper)
		if err != nil {
			conn.CloseWithError(0, "handshake failed")
			continue
		}
		return transport.Accepted{
			Conn: newConn(stream, conn.RemoteAddr().String()), VNI: auth.VNI, ClientPub: auth.ClientPub, Session: auth.Session,
			C2SKey: auth.C2SKey, S2CKey: auth.S2CKey,
		}, nil
	}
}

// pumpHopped feeds subsequent frames from a hopped connection's stream to the
// demux until the stream closes.
func (l *Listener) pumpHopped(conn *quic.Conn, stream *quic.Stream, sender func([]byte) error) {
	for {
		frame, err := readFrame(stream)
		if err != nil {
			conn.CloseWithError(0, "hopped stream closed")
			return
		}
		if l.demux == nil || !l.demux(conn.RemoteAddr().String(), frame, sender) {
			// The session went away; drop the connection.
			conn.CloseWithError(0, "hopped session gone")
			return
		}
	}
}

func (l *Listener) Close() error { return l.inner.Close() }
func (l *Listener) Addr() string { return l.inner.Addr().String() }

// --------------- framing helpers (match Conn's [len:2][payload]) ---------------

func readFrame(r io.Reader) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := int(binary.LittleEndian.Uint16(header[:]))
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeStreamFrame(stream *quic.Stream, data []byte) error {
	var header [2]byte
	binary.LittleEndian.PutUint16(header[:], uint16(len(data)))
	if _, err := stream.Write(header[:]); err != nil {
		return err
	}
	_, err := stream.Write(data)
	return err
}

// prefixedStream replays one already-read frame before the underlying stream.
type prefixedStream struct {
	*quic.Stream
	first    []byte
	consumed bool
	off      int
}

func (p *prefixedStream) Read(b []byte) (int, error) {
	// Serve the buffered first frame (as [len:2][payload]) before the stream.
	if !p.consumed {
		var hdr [2]byte
		binary.LittleEndian.PutUint16(hdr[:], uint16(len(p.first)))
		full := append(hdr[:], p.first...)
		n := copy(b, full[p.off:])
		p.off += n
		if p.off >= len(full) {
			p.consumed = true
		}
		return n, nil
	}
	return p.Stream.Read(b)
}
