// Package assign is the client<->operator CONTROL plane that runs AFTER
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
package assign

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

// Nonce counters for the control frames. The auth confirmation used counter 0
// on the same keys; the control plane continues from 1. Each direction has its
// own key, so client and operator counters are independent sequences.
const (
	ctrClaim = 1 // operator -> client: ServerClaim
	ctrAck   = 1 // client  -> operator: ClientAck
)

// aad domain-separates the assign control plane from auth and data frames.
var aad = []byte("gasoline-assign-v1")

// Code reports the outcome of an assignment.
type Code uint8

const (
	CodeOK       Code = 0x00
	CodeNoRoute  Code = 0x01 // pool exhausted / no address for this identity
	CodeConflict Code = 0x02 // identity already has a live session (PRD §8)
)

// Allocator is the operator-side policy the assign server drives. It is the
// two-phase-commit backend: Preclaim reserves, Confirm commits, Rollback frees.
// A local implementation is used today; the Raft-backed one lands in P4.
type Allocator interface {
	// Preclaim reserves an address for (vni, cid, pubkey) and returns it plus
	// the VNI's range. The address is held pending until Confirm or Rollback.
	Preclaim(vni protocol.VNI_Ty, cid protocol.CID_Ty, pubkey noise.PublicKey) (ip netip.Addr, ranges netip.Prefix, code Code)
	// Confirm commits a prior Preclaim (client acknowledged).
	Confirm(vni protocol.VNI_Ty, cid protocol.CID_Ty, ip netip.Addr)
	// Rollback releases a prior Preclaim (client never acknowledged).
	Rollback(vni protocol.VNI_Ty, cid protocol.CID_Ty, ip netip.Addr)
}

// ServerAssign runs the operator side of the two-phase assignment over rw,
// sealing with sess. cid/pubkey/vni come from the completed handshake. On
// success it returns the committed SessionContext.
func ServerAssign(
	conn Conn,
	sess *noise.Session,
	vni protocol.VNI_Ty,
	cid protocol.CID_Ty,
	pubkey noise.PublicKey,
	sessionIndex uint32,
	alloc Allocator,
) (*protocol.SessionContext, error) {
	// preclaim
	ip, ranges, code := alloc.Preclaim(vni, cid, pubkey)

	claim := serverClaim{Code: code, IP: ip, Ranges: ranges}
	if code == CodeOK {
		claim.SessionIndex = sessionIndex
	}
	if err := writeSealed(conn, sess, ctrClaim, claim.marshal()); err != nil {
		if code == CodeOK {
			alloc.Rollback(vni, cid, ip)
		}
		return nil, fmt.Errorf("send ServerClaim: %w", err)
	}
	if code != CodeOK {
		return nil, fmt.Errorf("assign rejected: code=%d", code)
	}

	// wait for ack
	ackBytes, err := readSealed(conn, sess, ctrAck)
	if err != nil {
		alloc.Rollback(vni, cid, ip)
		return nil, fmt.Errorf("recv ClientAck: %w", err)
	}
	var ack clientAck
	if err := ack.unmarshal(ackBytes); err != nil {
		alloc.Rollback(vni, cid, ip)
		return nil, fmt.Errorf("parse ClientAck: %w", err)
	}
	if !ack.Accepted {
		alloc.Rollback(vni, cid, ip)
		return nil, fmt.Errorf("client rejected assignment")
	}

	// confirm (commit)
	alloc.Confirm(vni, cid, ip)

	return &protocol.SessionContext{
		CID:          cid,
		VNI:          vni,
		SessionIndex: sessionIndex,
		IP:           ip,
		IPRanges:     ranges,
	}, nil
}

// ClientAssign runs the client side: receive the claimed IP, accept it, and
// return the resulting SessionContext.
func ClientAssign(conn Conn, sess *noise.Session, vni protocol.VNI_Ty, cid protocol.CID_Ty) (*protocol.SessionContext, error) {
	claimBytes, err := readSealed(conn, sess, ctrClaim)
	if err != nil {
		return nil, fmt.Errorf("recv ServerClaim: %w", err)
	}
	var claim serverClaim
	if err := claim.unmarshal(claimBytes); err != nil {
		return nil, fmt.Errorf("parse ServerClaim: %w", err)
	}
	if claim.Code != CodeOK {
		return nil, fmt.Errorf("assign rejected: code=%d", claim.Code)
	}

	// accept
	ack := clientAck{Accepted: true}
	if err := writeSealed(conn, sess, ctrAck, ack.marshal()); err != nil {
		return nil, fmt.Errorf("send ClientAck: %w", err)
	}

	return &protocol.SessionContext{
		CID:          cid,
		VNI:          vni,
		SessionIndex: claim.SessionIndex,
		IP:           claim.IP,
		IPRanges:     claim.Ranges,
	}, nil
}

// --------------- frames ---------------

// serverClaim: code(1) + sessionIndex(4) + ipLen(1) + ip + rangeLen(1) + range + rangeBits(1)
type serverClaim struct {
	Code         Code
	SessionIndex uint32
	IP           netip.Addr
	Ranges       netip.Prefix
}

func (c serverClaim) marshal() []byte {
	ip := c.IP.AsSlice()
	rng := c.Ranges.Addr().AsSlice()
	bits := byte(c.Ranges.Bits())
	if !c.Ranges.IsValid() {
		rng, bits = nil, 0
	}
	var b bytes.Buffer
	b.WriteByte(byte(c.Code))
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
	code, err := r.ReadByte()
	if err != nil {
		return err
	}
	c.Code = Code(code)
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

// clientAck: accepted(1) + sessionID(16)
type clientAck struct {
	Accepted  bool
	SessionID protocol.SessionID_Ty
}

func (a clientAck) marshal() []byte {
	b := make([]byte, 1+16)
	if a.Accepted {
		b[0] = 1
	}
	copy(b[1:], a.SessionID[:])
	return b
}

func (a *clientAck) unmarshal(b []byte) error {
	if len(b) < 1+16 {
		return fmt.Errorf("assign: short ClientAck %d", len(b))
	}
	a.Accepted = b[0] == 1
	copy(a.SessionID[:], b[1:17])
	return nil
}

// --------------- sealed framing ---------------
//
// One AEAD-sealed payload per frame; the transport delimits frames, so no
// length prefix is needed here.

// maxFrame bounds a control ciphertext read. Control payloads are tiny
// (< 64 bytes) plus the 16-byte tag; 512 is generous.
const maxFrame = 512

func writeSealed(conn Conn, sess *noise.Session, counter uint64, payload []byte) error {
	ct, err := sess.SealAt(counter, payload, aad)
	if err != nil {
		return err
	}
	return conn.WritePacket(ct)
}

func readSealed(conn Conn, sess *noise.Session, counter uint64) ([]byte, error) {
	buf := make([]byte, maxFrame)
	n, err := conn.ReadPacket(buf)
	if err != nil {
		return nil, err
	}
	return sess.OpenAt(counter, buf[:n], aad, false)
}
