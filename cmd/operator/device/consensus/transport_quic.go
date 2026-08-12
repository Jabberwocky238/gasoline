package consensus

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
)

// raftALPN is the QUIC ALPN token for the raft control channel.
const raftALPN = "gasoline-raft-v1"

// msgTransport ships etcd-raft messages between peers over QUIC. Each raft
// message is one length-prefixed frame on a short-lived stream. Peer addresses
// are resolved from the id->addr map; connections are dialed lazily and cached.
type msgTransport struct {
	ln       *quic.Listener
	tlsConf  *tls.Config
	quicConf *quic.Config
	addrs    map[uint64]string // raft id -> QUIC addr

	onRecv func([]byte) // set by Node before use; called per received message

	mu      sync.Mutex
	dials   map[uint64]*quic.Conn
	closeCh chan struct{}
	closed  sync.Once
}

func newMsgTransport(bindAddr string, serverTLS, clientTLS *tls.Config, addrs map[uint64]string) (*msgTransport, error) {
	sTLS := serverTLS.Clone()
	sTLS.NextProtos = []string{raftALPN}
	cTLS := clientTLS.Clone()
	cTLS.NextProtos = []string{raftALPN}
	qConf := &quic.Config{MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 10 * time.Second}

	ln, err := quic.ListenAddr(bindAddr, sTLS, qConf)
	if err != nil {
		return nil, fmt.Errorf("consensus: quic listen %s: %w", bindAddr, err)
	}
	t := &msgTransport{
		ln:       ln,
		tlsConf:  cTLS,
		quicConf: qConf,
		addrs:    addrs,
		dials:    make(map[uint64]*quic.Conn),
		closeCh:  make(chan struct{}),
	}
	go t.acceptLoop()
	return t, nil
}

func (t *msgTransport) acceptLoop() {
	for {
		conn, err := t.ln.Accept(context.Background())
		if err != nil {
			return
		}
		go t.serveConn(conn)
	}
}

func (t *msgTransport) serveConn(conn *quic.Conn) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go t.serveStream(stream)
	}
}

func (t *msgTransport) serveStream(stream *quic.Stream) {
	defer stream.Close()
	data, err := readMsgFrame(stream)
	if err != nil {
		return
	}
	if t.onRecv != nil {
		t.onRecv(data)
	}
}

// send delivers each raft message to its target peer. Failures are dropped —
// raft retries on its own cadence, so a transient send error is not fatal.
func (t *msgTransport) send(msgs []*raftpb.Message) {
	for _, m := range msgs {
		data, err := proto.Marshal(m)
		if err != nil {
			continue
		}
		go t.sendTo(m.GetTo(), data)
	}
}

func (t *msgTransport) sendTo(to uint64, data []byte) {
	addr, ok := t.addrs[to]
	if !ok {
		return
	}
	conn, err := t.conn(to, addr)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.drop(to, conn)
		return
	}
	defer stream.Close()
	_ = writeMsgFrame(stream, data)
}

// conn returns a cached connection to peer, dialing if necessary.
func (t *msgTransport) conn(to uint64, addr string) (*quic.Conn, error) {
	t.mu.Lock()
	c := t.dials[to]
	t.mu.Unlock()
	if c != nil {
		return c, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := quic.DialAddr(ctx, addr, t.tlsConf, t.quicConf)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	if existing := t.dials[to]; existing != nil {
		_ = c.CloseWithError(0, "dup")
		c = existing
	} else {
		t.dials[to] = c
	}
	t.mu.Unlock()
	return c, nil
}

func (t *msgTransport) drop(to uint64, conn *quic.Conn) {
	t.mu.Lock()
	if t.dials[to] == conn {
		delete(t.dials, to)
	}
	t.mu.Unlock()
	_ = conn.CloseWithError(0, "send failed")
}

func (t *msgTransport) close() error {
	t.closed.Do(func() { close(t.closeCh) })
	t.mu.Lock()
	for _, c := range t.dials {
		_ = c.CloseWithError(0, "closing")
	}
	t.dials = map[uint64]*quic.Conn{}
	t.mu.Unlock()
	return t.ln.Close()
}

// --------------- length-prefixed framing ---------------

func writeMsgFrame(w io.Writer, data []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func readMsgFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > (1 << 24) { // 16 MiB cap
		return nil, fmt.Errorf("consensus: raft msg too large: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
