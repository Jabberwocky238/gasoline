package consensus

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/hashicorp/raft"
	"github.com/quic-go/quic-go"
)

// Command forwarding (follower -> leader).
//
// hashicorp/raft's Apply only works on the leader; a follower must ship the
// command to the leader to be ordered + committed (PRD §2.3 — "跟随者收到握手
// 时把 Raft 写入转发给 leader"). This is a small reliable request/response over
// QUIC: the follower dials the leader's forward listener, sends one gob-encoded
// Command, the leader Applies it and returns the ApplyResult's error string.
//
// The forward listener runs on the node's Raft bind host at (raftPort +
// forwardPortOffset), reusing the Raft transport's TLS. A follower derives the
// leader's forward address the same way from LeaderWithID()'s Raft address.

const (
	forwardPortOffset = 1
	forwardALPN       = "gaso-fwd"
	maxForwardFrame   = 1 << 20 // 1 MiB; commands are tiny
)

// forwardServer accepts forwarded commands on the leader and applies them.
type forwardServer struct {
	ln   *quic.Listener
	node *Node
}

// startForwardServer binds the forward listener at host:(port+offset).
func startForwardServer(node *Node, raftBind string, serverTLS *tls.Config) (*forwardServer, error) {
	addr, err := forwardAddr(raftBind)
	if err != nil {
		return nil, err
	}
	tc := serverTLS.Clone()
	tc.NextProtos = []string{forwardALPN}
	ln, err := quic.ListenAddr(addr, tc, nil)
	if err != nil {
		return nil, fmt.Errorf("consensus: forward listen %q: %w", addr, err)
	}
	fs := &forwardServer{ln: ln, node: node}
	go fs.acceptLoop()
	return fs, nil
}

func (fs *forwardServer) acceptLoop() {
	for {
		conn, err := fs.ln.Accept(context.Background())
		if err != nil {
			return // listener closed
		}
		go fs.serveConn(conn)
	}
}

func (fs *forwardServer) serveConn(conn *quic.Conn) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go fs.serveStream(stream)
	}
}

// serveStream reads one length-prefixed Command, applies it locally (this node
// is the leader), and writes back a length-prefixed error string ("" = ok).
func (fs *forwardServer) serveStream(stream *quic.Stream) {
	defer stream.Close()
	data, err := readFrame(stream)
	if err != nil {
		return
	}
	cmd, err := DecodeCommand(data)
	var replyErr string
	if err != nil {
		replyErr = err.Error()
	} else if applyErr := fs.node.applyLocalLeader(cmd, 5*time.Second); applyErr != nil {
		replyErr = applyErr.Error()
	}
	_ = writeFrame(stream, []byte(replyErr))
}

func (fs *forwardServer) close() {
	if fs != nil && fs.ln != nil {
		_ = fs.ln.Close()
	}
}

// applyLocalLeader applies a command directly through Raft on the leader. It is
// the non-forwarding half of Propose, called both by a leader's own Propose and
// by the forward server on behalf of a follower.
func (n *Node) applyLocalLeader(cmd *Command, timeout time.Duration) error {
	data, err := cmd.Encode()
	if err != nil {
		return err
	}
	f := n.raft.Apply(data, timeout)
	if err := f.Error(); err != nil {
		return err
	}
	if res, ok := f.Response().(ApplyResult); ok {
		return res.Err
	}
	return nil
}

// forwardToLeader dials the current leader's forward listener and submits cmd,
// returning the leader's apply result. Used by Propose on a follower.
func (n *Node) forwardToLeader(cmd *Command, timeout time.Duration) error {
	raftAddr, _ := n.raft.LeaderWithID()
	if raftAddr == "" {
		return raft.ErrLeader // no known leader yet; caller retries
	}
	fwdAddr, err := forwardAddr(string(raftAddr))
	if err != nil {
		return err
	}
	data, err := cmd.Encode()
	if err != nil {
		return err
	}

	tc := n.clientTLS.Clone()
	tc.NextProtos = []string{forwardALPN}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := quic.DialAddr(ctx, fwdAddr, tc, nil)
	if err != nil {
		return fmt.Errorf("consensus: dial leader %q: %w", fwdAddr, err)
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()
	if err := writeFrame(stream, data); err != nil {
		return err
	}
	replyErr, err := readFrame(stream)
	if err != nil {
		return err
	}
	if len(replyErr) > 0 {
		return fmt.Errorf("%s", string(replyErr))
	}
	return nil
}

// forwardAddr maps a Raft bind/leader address to its forward listener address:
// same host, port + forwardPortOffset.
func forwardAddr(raftAddr string) (string, error) {
	host, portStr, err := net.SplitHostPort(raftAddr)
	if err != nil {
		return "", fmt.Errorf("consensus: bad raft addr %q: %w", raftAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", fmt.Errorf("consensus: bad raft port %q: %w", portStr, err)
	}
	return net.JoinHostPort(host, strconv.Itoa(port+forwardPortOffset)), nil
}

// --------------- length-prefixed framing ---------------

func writeFrame(w io.Writer, data []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxForwardFrame {
		return nil, fmt.Errorf("consensus: forward frame too large: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
