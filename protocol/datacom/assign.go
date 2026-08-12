// assign.go — the client<->operator CONTROL plane that runs AFTER
// authentication (package handshake). It assigns an overlay IP and session in a
// SINGLE frame (PRD §2.3, post-2PC): the operator commits the session through
// Raft — the leader's Apply allocates a free IP deterministically, so there is
// no pre-selection, no ack, no rollback, no collision-retry — and sends the
// result to the client in one AEAD-sealed frame.
//
// The frame is sealed under the authenticated noise.Session, so the control
// plane inherits the handshake's confidentiality and the client's identity.
// This package does NOT authenticate — the caller passes a Session that
// handshake already produced.
package datacom

import (
	"bytes"
	"encoding/binary"
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

// The single assign frame seals at counter 1 (the auth key-confirmation used
// counter 0 on the same keys).
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

// Allocator is the operator-side backend the assign server drives. Assign
// commits the session through Raft in one shot and returns the address the
// leader's Apply allocated (deterministic first-free — no pre-selection). It
// returns CodeNoRoute when the pool is exhausted or the key is not granted.
type Allocator interface {
	Assign(vni protocol.VNI_Ty, pubkey noise.PublicKey, sessionID protocol.SessionID_Ty, keys DataKeys) (ip netip.Addr, ranges netip.Prefix, code Code)
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

// ServerAssign runs the operator side of the single-frame assignment over conn,
// sealing with sess. pubkey/vni come from the completed handshake. It commits
// the session (Allocator.Assign → Raft), then sends one result frame carrying
// the allocated IP / SessionID / hop-server list. On success it returns the
// SessionContext.
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
	sessionID := protocol.NewSessionID()
	ip, ranges, code := alloc.Assign(vni, pubkey, sessionID, keys)

	res := assignResult{Code: code, SessionID: sessionID, SessionIndex: sessionIndex, IP: ip, Ranges: ranges}
	if code == CodeOK {
		res.Servers = servers
	}
	if err := writeSealed(conn, sess, ctrlBase, res.marshal()); err != nil {
		return nil, fmt.Errorf("send assign result: %w", err)
	}
	if code != CodeOK {
		return nil, fmt.Errorf("assign rejected: code=%d", code)
	}
	return &protocol.SessionContext{
		SessionID:    sessionID,
		VNI:          vni,
		SessionIndex: sessionIndex,
		IP:           ip,
		IPRanges:     ranges,
	}, nil
}

// ClientAssign runs the client side: receive the single result frame and return
// the resulting SessionContext (with its hop-server list).
func ClientAssign(conn Conn, sess *noise.Session, vni protocol.VNI_Ty) (*protocol.SessionContext, error) {
	frame, _, err := readSealed(conn, sess)
	if err != nil {
		return nil, fmt.Errorf("recv assign result: %w", err)
	}
	var res assignResult
	if err := res.unmarshal(frame); err != nil {
		return nil, fmt.Errorf("parse assign result: %w", err)
	}
	if res.Code != CodeOK {
		return nil, fmt.Errorf("assign rejected: code=%d", res.Code)
	}
	sc := &protocol.SessionContext{
		SessionID:    res.SessionID,
		VNI:          vni,
		SessionIndex: res.SessionIndex,
		IP:           res.IP,
		IPRanges:     res.Ranges,
	}
	sc.SetServers(serverListToContext(res.Servers))
	return sc, nil
}

// --------------- frame ---------------

// assignResult is the single operator -> client frame:
//
//	code(1) sessionID(16) sessionIndex(4)
//	ipLen(1) ip rangeLen(1) range rangeBits(1)
//	serverList(...)
type assignResult struct {
	Code         Code
	SessionID    protocol.SessionID_Ty
	SessionIndex uint32
	IP           netip.Addr
	Ranges       netip.Prefix
	Servers      ServerList
}

func (c assignResult) marshal() []byte {
	ip := c.IP.AsSlice()
	rng := c.Ranges.Addr().AsSlice()
	bits := byte(c.Ranges.Bits())
	if !c.Ranges.IsValid() {
		rng, bits = nil, 0
	}
	var b bytes.Buffer
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
	b.Write(marshalServerList(c.Servers))
	return b.Bytes()
}

func (c *assignResult) unmarshal(b []byte) error {
	r := bytes.NewReader(b)
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
	rest, _ := io.ReadAll(r)
	servers, err := unmarshalServerList(rest)
	if err != nil {
		return err
	}
	c.Servers = servers
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

// --------------- sealed framing ---------------
//
// Wire: counter(8, big-endian) || AEAD(session, counter, payload). The counter
// travels in the clear (a nonce needn't be secret) so the peer reconstructs the
// nonce. The transport delimits frames.

// maxFrame bounds a control ciphertext read. The assign result carries the hop
// server list, so it can be larger than the old tiny control frames; 8 KiB is
// generous for a mesh of many operators.
const maxFrame = 8192

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
