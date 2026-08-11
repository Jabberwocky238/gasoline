// assign.go — the client<->operator CONTROL plane that runs AFTER
// authentication (package handshake). It assigns an overlay IP and session
// using a two-phase commit so a claimed-but-unacknowledged address is never
// leaked:
//
//	preclaim : operator reserves a free IP (pending) — after auth, so an
//	           unauthenticated peer can never touch the pool
//	claim    : operator sends the reserved IP to the client (ServerClaim)
//	ack      : client accepts (ClientAck)
//	confirm  : operator commits the reservation; on ack timeout it rolls back
//
// All frames are AEAD-sealed under the authenticated noise.Session, so the
// control plane inherits the handshake's confidentiality and the client's
// identity. This package does NOT authenticate — the caller passes a Session
// that handshake already produced.
package datacom

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/noise"
)

// Conn is the packet-oriented connection the assign control plane runs over —
// exactly transport.Conn's read/write pair, so a transport.Conn satisfies it
// directly with no adapter. One WritePacket is one frame; one ReadPacket
// returns exactly one. The transport delimits frames, so assign needs no
// length framing of its own.
type Conn interface {
	WritePacket(data []byte) error
	ReadPacket(buf []byte) (int, error)
}

// Control frames carry an explicit 8-byte counter prefix so each side can seal
// with a monotonically increasing nonce. This matters for the collision-retry
// loop: a rejected claim is re-sent under a fresh counter, never reusing a
// nonce. The auth key-confirmation used counter 0; the control plane starts at
// 1 in each direction (independent keys => independent sequences).
const ctrlBase = 1

// aadAssign domain-separates the assign control plane from auth and data frames.
var aadAssign = []byte("gasoline-assign-v1")

// Code reports the outcome of an assignment.
type Code uint8

const (
	CodeOK       Code = 0x00
	CodeNoRoute  Code = 0x01 // pool exhausted / no address for this identity
	CodeConflict Code = 0x02 // identity already has a live session (PRD §8)
)

// frameKind is the first byte of every control payload, letting the client
// distinguish a (re)claim from the terminal commit.
type frameKind uint8

const (
	kindClaim   frameKind = 0x01 // operator -> client: here is a proposed IP
	kindConfirm frameKind = 0x02 // operator -> client: committed, assignment final
)

// Reservation is what a successful Preclaim yields: the reserved IP, the VNI's
// range, and the cluster-unique SessionID minted for this session. IP and
// SessionID are allocated together (one Raft log entry in the consensus path).
type Reservation struct {
	IP        netip.Addr
	Ranges    netip.Prefix
	SessionID protocol.SessionID_Ty
	Keys      DataKeys // data-plane keys to persist at Confirm (PRD §7.2)
}

// Allocator is the operator-side policy the assign server drives, a two-phase
// commit backend:
//
//   - Preclaim optimistically picks a free IP + mints a SessionID by reading
//     local state. It does NOT commit — a claimed-but-unacknowledged address
//     never enters the durable store, so it can't leak.
//   - Confirm (after the client acks) durably commits the reservation. In the
//     Raft-backed allocator this proposes SessionCreate; if another node
//     committed the same IP first, Confirm returns ErrIPConflict and the assign
//     server retries with a fresh Preclaim.
//   - Rollback releases an unacknowledged Preclaim (no-op when Preclaim held no
//     durable state).
type Allocator interface {
	Preclaim(vni protocol.VNI_Ty, pubkey noise.PublicKey) (Reservation, Code)
	Confirm(vni protocol.VNI_Ty, pubkey noise.PublicKey, r Reservation) error
	Rollback(vni protocol.VNI_Ty, r Reservation)
}

// DataKeys are the raw directional data-plane transport keys the handshake
// derived, carried into the assignment so the Raft-backed allocator can
// replicate them (PRD §7.2). C2SKey decrypts client->PE, S2CKey encrypts
// PE->client.
type DataKeys struct {
	C2SKey [32]byte
	S2CKey [32]byte
}

// PortRange is an inclusive UDP port interval a server accepts hopping traffic
// on (PRD §5/§6.2). Lo == Hi is a single port.
type PortRange struct {
	Lo uint16
	Hi uint16
}

// ServerEndpoint is one operator a client may hop its data frames to: its host,
// the port ranges it listens on, and its UUID. The client picks any (endpoint,
// port-in-range) at random each hop interval (PRD §5.1 — hopping is random).
type ServerEndpoint struct {
	UUID  [16]byte
	Host  netip.Addr
	Ports []PortRange
}

// ServerList is the authoritative set of hop targets the operator hands the
// client in the final assignment frame (PRD §5.3 / §6.2). It overrides whatever
// the client had locally, which may be stale.
type ServerList []ServerEndpoint

// serverListToContext converts the wire ServerList into the protocol-level hop
// targets stored on a SessionContext.
func serverListToContext(list ServerList) []protocol.HopServer {
	if len(list) == 0 {
		return nil
	}
	out := make([]protocol.HopServer, 0, len(list))
	for _, e := range list {
		hs := protocol.HopServer{UUID: e.UUID, Host: e.Host}
		for _, p := range e.Ports {
			hs.Ports = append(hs.Ports, protocol.HopPortRange{Lo: p.Lo, Hi: p.Hi})
		}
		out = append(out, hs)
	}
	return out
}

// ErrIPConflict is returned by Confirm when the reserved IP was committed by
// another node between Preclaim and Confirm. The assign server retries.
var ErrIPConflict = errors.New("assign: ip conflict, retry")

// maxAllocRetries bounds the optimistic-concurrency retry loop.
const maxAllocRetries = 3

// ServerAssign runs the operator side of the two-phase assignment over conn,
// sealing with sess. pubkey/vni come from the completed handshake. On success
// it returns the committed SessionContext (IP + SessionID).
func ServerAssign(
	conn Conn,
	sess *noise.Session,
	vni protocol.VNI_Ty,
	pubkey noise.PublicKey,
	sessionIndex uint32,
	keys DataKeys,
	servers ServerList,
	alloc Allocator,
) (*protocol.SessionContext, error) {
	sendCtr := uint64(ctrlBase) // operator's monotonic send counter
	for attempt := 0; attempt < maxAllocRetries; attempt++ {
		// Preclaim: optimistically pick IP + SessionID (no durable write yet).
		res, code := alloc.Preclaim(vni, pubkey)
		res.Keys = keys // carry data-plane keys into Confirm (PRD §7.2)

		claim := serverClaim{Kind: kindClaim, Code: code, IP: res.IP, Ranges: res.Ranges, SessionID: res.SessionID}
		if code == CodeOK {
			claim.SessionIndex = sessionIndex
		}
		if err := writeSealed(conn, sess, sendCtr, claim.marshal()); err != nil {
			if code == CodeOK {
				alloc.Rollback(vni, res)
			}
			return nil, fmt.Errorf("send ServerClaim: %w", err)
		}
		sendCtr++
		if code != CodeOK {
			return nil, fmt.Errorf("assign rejected: code=%d", code)
		}

		// Wait for the client to accept.
		ackBytes, _, err := readSealed(conn, sess)
		if err != nil {
			alloc.Rollback(vni, res)
			return nil, fmt.Errorf("recv ClientAck: %w", err)
		}
		var ack clientAck
		if err := ack.unmarshal(ackBytes); err != nil {
			alloc.Rollback(vni, res)
			return nil, fmt.Errorf("parse ClientAck: %w", err)
		}
		if !ack.Accepted {
			alloc.Rollback(vni, res)
			return nil, fmt.Errorf("client rejected assignment")
		}

		// Confirm: durably commit. On IP conflict (another node took this
		// address between Preclaim and Confirm) retry the whole claim/ack with a
		// fresh pick. On success send a terminal Confirm frame so the client
		// knows this claim is final (and not a prelude to a retry).
		err = alloc.Confirm(vni, pubkey, res)
		if err == nil {
			done := serverClaim{Kind: kindConfirm, Servers: servers}
			if werr := writeSealed(conn, sess, sendCtr, done.marshal()); werr != nil {
				return nil, fmt.Errorf("send Confirm: %w", werr)
			}
			return &protocol.SessionContext{
				SessionID:    res.SessionID,
				VNI:          vni,
				SessionIndex: sessionIndex,
				IP:           res.IP,
				IPRanges:     res.Ranges,
			}, nil
		}
		alloc.Rollback(vni, res)
		if !errors.Is(err, ErrIPConflict) {
			return nil, fmt.Errorf("confirm: %w", err)
		}
		// conflict: loop and re-pick (next claim uses the next sendCtr).
	}
	return nil, fmt.Errorf("assign: exhausted %d allocation retries", maxAllocRetries)
}

// ClientAssign runs the client side: receive a claimed IP + SessionID, accept
// it, and return the resulting SessionContext. If the operator hit an IP
// collision it re-claims a fresh address, so the client loops until it gets a
// claim the operator can commit (bounded by the operator's retry budget).
func ClientAssign(conn Conn, sess *noise.Session, vni protocol.VNI_Ty) (*protocol.SessionContext, error) {
	sendCtr := uint64(ctrlBase) // client's monotonic send counter
	var last serverClaim        // the most recent claim we accepted
	for attempt := 0; attempt < maxAllocRetries+2; attempt++ {
		frame, _, err := readSealed(conn, sess)
		if err != nil {
			return nil, fmt.Errorf("recv ServerClaim: %w", err)
		}
		var claim serverClaim
		if err := claim.unmarshal(frame); err != nil {
			return nil, fmt.Errorf("parse ServerClaim: %w", err)
		}

		switch claim.Kind {
		case kindConfirm:
			// Committed. Finalize with the last claim we accepted. The confirm
			// frame carries the authoritative hop-target list (PRD §5.3 / §6.2).
			if last.SessionID == (protocol.SessionID_Ty{}) && !last.IP.IsValid() {
				return nil, fmt.Errorf("assign: confirm before any claim")
			}
			sc := &protocol.SessionContext{
				SessionID:    last.SessionID,
				VNI:          vni,
				SessionIndex: last.SessionIndex,
				IP:           last.IP,
				IPRanges:     last.Ranges,
			}
			sc.SetServers(serverListToContext(claim.Servers))
			return sc, nil

		case kindClaim:
			if claim.Code != CodeOK {
				return nil, fmt.Errorf("assign rejected: code=%d", claim.Code)
			}
			last = claim
			ack := clientAck{Accepted: true}
			if err := writeSealed(conn, sess, sendCtr, ack.marshal()); err != nil {
				return nil, fmt.Errorf("send ClientAck: %w", err)
			}
			sendCtr++

		default:
			return nil, fmt.Errorf("assign: unknown frame kind %#x", byte(claim.Kind))
		}
	}
	return nil, fmt.Errorf("assign: exhausted retries")
}

// --------------- frames ---------------

// serverClaim: kind(1). For kindClaim also: code(1) + sessionID(16) +
// sessionIndex(4) + ipLen(1) + ip + rangeLen(1) + range + rangeBits(1).
// kindConfirm carries kind(1) + the marshalled ServerList (hop targets).
type serverClaim struct {
	Kind         frameKind
	Code         Code
	SessionID    protocol.SessionID_Ty
	SessionIndex uint32
	IP           netip.Addr
	Ranges       netip.Prefix
	Servers      ServerList // populated on kindConfirm only
}

func (c serverClaim) marshal() []byte {
	if c.Kind == kindConfirm {
		return append([]byte{byte(kindConfirm)}, marshalServerList(c.Servers)...)
	}
	ip := c.IP.AsSlice()
	rng := c.Ranges.Addr().AsSlice()
	bits := byte(c.Ranges.Bits())
	if !c.Ranges.IsValid() {
		rng, bits = nil, 0
	}
	var b bytes.Buffer
	b.WriteByte(byte(kindClaim))
	b.WriteByte(byte(c.Code))
	b.Write(c.SessionID[:])
	var idx [4]byte
	binary.BigEndian.PutUint32(idx[:], c.SessionIndex)
	b.Write(idx[:])
	b.WriteByte(byte(len(ip)))
	b.Write(ip)
	b.WriteByte(byte(len(rng)))
	b.Write(rng)
	b.WriteByte(bits)
	return b.Bytes()
}

func (c *serverClaim) unmarshal(b []byte) error {
	r := bytes.NewReader(b)
	kind, err := r.ReadByte()
	if err != nil {
		return err
	}
	c.Kind = frameKind(kind)
	if c.Kind == kindConfirm {
		rest, _ := io.ReadAll(r)
		servers, err := unmarshalServerList(rest)
		if err != nil {
			return err
		}
		c.Servers = servers
		return nil
	}
	code, err := r.ReadByte()
	if err != nil {
		return err
	}
	c.Code = Code(code)
	if _, err := io.ReadFull(r, c.SessionID[:]); err != nil {
		return err
	}
	var idx [4]byte
	if _, err := io.ReadFull(r, idx[:]); err != nil {
		return err
	}
	c.SessionIndex = binary.BigEndian.Uint32(idx[:])
	ipLen, err := r.ReadByte()
	if err != nil {
		return err
	}
	if ipLen > 0 {
		buf := make([]byte, ipLen)
		if _, err := io.ReadFull(r, buf); err != nil {
			return err
		}
		if a, ok := netip.AddrFromSlice(buf); ok {
			c.IP = a
		}
	}
	rngLen, err := r.ReadByte()
	if err != nil {
		return err
	}
	var rngAddr netip.Addr
	if rngLen > 0 {
		buf := make([]byte, rngLen)
		if _, err := io.ReadFull(r, buf); err != nil {
			return err
		}
		if a, ok := netip.AddrFromSlice(buf); ok {
			rngAddr = a
		}
	}
	bits, err := r.ReadByte()
	if err != nil {
		return err
	}
	if rngAddr.IsValid() {
		c.Ranges = netip.PrefixFrom(rngAddr, int(bits))
	}
	return nil
}

// marshalServerList encodes a ServerList:
//
//	count(1) [ uuid(16) hostLen(1) host portCount(1) [lo(2) hi(2)]... ]...
//
// host is 4 or 16 raw address bytes. An empty list encodes as a single 0 byte.
func marshalServerList(list ServerList) []byte {
	var b bytes.Buffer
	b.WriteByte(byte(len(list)))
	for _, e := range list {
		b.Write(e.UUID[:])
		host := e.Host.AsSlice()
		b.WriteByte(byte(len(host)))
		b.Write(host)
		b.WriteByte(byte(len(e.Ports)))
		for _, p := range e.Ports {
			var buf [4]byte
			binary.BigEndian.PutUint16(buf[0:2], p.Lo)
			binary.BigEndian.PutUint16(buf[2:4], p.Hi)
			b.Write(buf[:])
		}
	}
	return b.Bytes()
}

// unmarshalServerList decodes what marshalServerList produced. An empty input
// (or a leading 0 count) yields a nil list, not an error.
func unmarshalServerList(b []byte) (ServerList, error) {
	if len(b) == 0 {
		return nil, nil
	}
	r := bytes.NewReader(b)
	count, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}
	list := make(ServerList, 0, count)
	for i := 0; i < int(count); i++ {
		var e ServerEndpoint
		if _, err := io.ReadFull(r, e.UUID[:]); err != nil {
			return nil, err
		}
		hostLen, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		host := make([]byte, hostLen)
		if _, err := io.ReadFull(r, host); err != nil {
			return nil, err
		}
		if a, ok := netip.AddrFromSlice(host); ok {
			e.Host = a
		}
		portCount, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		for j := 0; j < int(portCount); j++ {
			var buf [4]byte
			if _, err := io.ReadFull(r, buf[:]); err != nil {
				return nil, err
			}
			e.Ports = append(e.Ports, PortRange{
				Lo: binary.BigEndian.Uint16(buf[0:2]),
				Hi: binary.BigEndian.Uint16(buf[2:4]),
			})
		}
		list = append(list, e)
	}
	return list, nil
}

// clientAck: accepted(1)
type clientAck struct {
	Accepted bool
}

func (a clientAck) marshal() []byte {
	if a.Accepted {
		return []byte{1}
	}
	return []byte{0}
}

func (a *clientAck) unmarshal(b []byte) error {
	if len(b) < 1 {
		return fmt.Errorf("assign: short ClientAck %d", len(b))
	}
	a.Accepted = b[0] == 1
	return nil
}

// --------------- sealed framing ---------------
//
// Wire: counter(8, big-endian) || AEAD(session, counter, payload). The counter
// travels in the clear (a nonce needn't be secret) so the peer reconstructs the
// nonce and the sequence survives retries. The transport delimits frames.

// maxFrame bounds a control ciphertext read. Control payloads are tiny
// (< 64 bytes) plus 8-byte counter + 16-byte tag; 512 is generous.
const maxFrame = 512

func writeSealed(conn Conn, sess *noise.Session, counter uint64, payload []byte) error {
	ct, err := sess.SealAt(counter, payload, aadAssign)
	if err != nil {
		return err
	}
	frame := make([]byte, 8+len(ct))
	binary.BigEndian.PutUint64(frame[:8], counter)
	copy(frame[8:], ct)
	return conn.WritePacket(frame)
}

// readSealed reads one frame and decrypts it under the counter carried in its
// header. It returns the payload and the counter (so the caller can advance its
// own receive sequence).
func readSealed(conn Conn, sess *noise.Session) ([]byte, uint64, error) {
	buf := make([]byte, maxFrame)
	n, err := conn.ReadPacket(buf)
	if err != nil {
		return nil, 0, err
	}
	if n < 8 {
		return nil, 0, fmt.Errorf("assign: short frame %d", n)
	}
	counter := binary.BigEndian.Uint64(buf[:8])
	pt, err := sess.OpenAt(counter, buf[8:n], aadAssign, false)
	return pt, counter, err
}
