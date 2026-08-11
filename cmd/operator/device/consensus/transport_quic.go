package consensus

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/raft"
	"github.com/quic-go/quic-go"
)

// raftALPN is the QUIC ALPN token for the Raft control channel. Keeping it
// distinct from the client data plane prevents cross-wiring.
const raftALPN = "gasoline-raft-v1"

// quicStreamLayer implements raft.StreamLayer (net.Listener + Dial) over QUIC.
// Each Raft RPC rides one bidirectional QUIC stream; connections to peers are
// dialed lazily and cached.
type quicStreamLayer struct {
	ln       *quic.Listener
	tlsConf  *tls.Config
	quicConf *quic.Config

	acceptCh chan net.Conn
	closeCh  chan struct{}
	closeOne sync.Once

	mu    sync.Mutex
	dials map[string]*quic.Conn // remote addr -> established connection
}

// newQUICStreamLayer binds a QUIC listener on bindAddr and returns a
// StreamLayer ready to hand to raft.NewNetworkTransport.
func newQUICStreamLayer(bindAddr string, serverTLS, clientTLS *tls.Config) (*quicStreamLayer, error) {
	sTLS := serverTLS.Clone()
	sTLS.NextProtos = []string{raftALPN}
	cTLS := clientTLS.Clone()
	cTLS.NextProtos = []string{raftALPN}

	qConf := &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	}
	ln, err := quic.ListenAddr(bindAddr, sTLS, qConf)
	if err != nil {
		return nil, fmt.Errorf("consensus: quic listen %s: %w", bindAddr, err)
	}
	sl := &quicStreamLayer{
		ln:       ln,
		tlsConf:  cTLS,
		quicConf: qConf,
		acceptCh: make(chan net.Conn, 16),
		closeCh:  make(chan struct{}),
		dials:    make(map[string]*quic.Conn),
	}
	go sl.acceptLoop()
	return sl, nil
}

// acceptLoop pulls incoming QUIC connections and their first stream, feeding
// them to Accept(). raft's NetworkTransport opens one stream per RPC, so we
// accept every stream on every connection.
func (s *quicStreamLayer) acceptLoop() {
	for {
		conn, err := s.ln.Accept(context.Background())
		if err != nil {
			select {
			case <-s.closeCh:
				return
			default:
				return
			}
		}
		go s.serveConn(conn)
	}
}

func (s *quicStreamLayer) serveConn(conn *quic.Conn) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		wrapped := &quicConn{stream: stream, local: conn.LocalAddr(), remote: conn.RemoteAddr()}
		select {
		case s.acceptCh <- wrapped:
		case <-s.closeCh:
			_ = stream.Close()
			return
		}
	}
}

// Accept implements net.Listener.
func (s *quicStreamLayer) Accept() (net.Conn, error) {
	select {
	case c := <-s.acceptCh:
		return c, nil
	case <-s.closeCh:
		return nil, fmt.Errorf("consensus: stream layer closed")
	}
}

// Close implements net.Listener.
func (s *quicStreamLayer) Close() error {
	s.closeOne.Do(func() { close(s.closeCh) })
	s.mu.Lock()
	for _, c := range s.dials {
		_ = c.CloseWithError(0, "closing")
	}
	s.dials = map[string]*quic.Conn{}
	s.mu.Unlock()
	return s.ln.Close()
}

// Addr implements net.Listener.
func (s *quicStreamLayer) Addr() net.Addr { return s.ln.Addr() }

// Dial implements raft.StreamLayer: open a new stream to address, reusing a
// cached QUIC connection when one exists.
func (s *quicStreamLayer) Dial(address raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	addr := string(address)

	s.mu.Lock()
	conn := s.dials[addr]
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if conn == nil {
		var err error
		conn, err = quic.DialAddr(ctx, addr, s.tlsConf, s.quicConf)
		if err != nil {
			return nil, fmt.Errorf("consensus: quic dial %s: %w", addr, err)
		}
		s.mu.Lock()
		// Another goroutine may have raced us; keep one.
		if existing := s.dials[addr]; existing != nil {
			_ = conn.CloseWithError(0, "dup")
			conn = existing
		} else {
			s.dials[addr] = conn
		}
		s.mu.Unlock()
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		// Cached connection may be dead; drop it so the next Dial reconnects.
		s.mu.Lock()
		if s.dials[addr] == conn {
			delete(s.dials, addr)
		}
		s.mu.Unlock()
		_ = conn.CloseWithError(0, "stream open failed")
		return nil, fmt.Errorf("consensus: quic open stream %s: %w", addr, err)
	}
	return &quicConn{stream: stream, local: conn.LocalAddr(), remote: conn.RemoteAddr()}, nil
}

// quicConn adapts a *quic.Stream to net.Conn. The stream carries Read/Write/
// Close/deadlines; the addresses come from the parent QUIC connection.
type quicConn struct {
	stream *quic.Stream
	local  net.Addr
	remote net.Addr
}

func (c *quicConn) Read(b []byte) (int, error)  { return c.stream.Read(b) }
func (c *quicConn) Write(b []byte) (int, error) { return c.stream.Write(b) }
func (c *quicConn) Close() error                { return c.stream.Close() }
func (c *quicConn) LocalAddr() net.Addr         { return c.local }
func (c *quicConn) RemoteAddr() net.Addr        { return c.remote }
func (c *quicConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}
func (c *quicConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}
func (c *quicConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}
