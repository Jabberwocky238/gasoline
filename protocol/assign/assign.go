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

// Reservation is what a successful Preclaim yields: the reserved IP, the VNI's
// range, and the cluster-unique SessionID minted for this session. IP and
// SessionID are allocated together (one Raft log entry in the consensus path).
type Reservation struct {
	IP        netip.Addr
	Ranges    netip.Prefix
	SessionID protocol.SessionID_Ty
}

// Allocator is the operator-side policy the assign server drives. It is the
// two-phase-commit backend: Preclaim reserves (IP + SessionID), Confirm
// commits, Rollback frees. Local impl today; Raft-backed lands in P4.
type Allocator interface {
	// Preclaim reserves an IP + SessionID for pubkey on vni. Held pending until
	// Confirm or Rollback.
	Preclaim(vni protocol.VNI_Ty, pubkey noise.PublicKey) (Reservation, Code)
	// Confirm commits a prior Preclaim (client acknowledged).
	Confirm(vni protocol.VNI_Ty, r Reservation)
	// Rollback releases a prior Preclaim (client never acknowledged).
	Rollback(vni protocol.VNI_Ty, r Reservation)
}

// ServerAssign runs the operator side of the two-phase assignment over conn,
// sealing with sess. pubkey/vni come from the completed handshake. On success
// it returns the committed SessionContext (IP + SessionID).
func ServerAssign(
	conn Conn,
	sess *noise.Session,
	vni protocol.VNI_Ty,
	pubkey noise.PublicKey,
	sessionIndex uint32,
	alloc Allocator,
) (*protocol.SessionContext, error) {
	// preclaim: reserve IP + SessionID together
	res, code := alloc.Preclaim(vni, pubkey)

	claim := serverClaim{Code: code, IP: res.IP, Ranges: res.Ranges, SessionID: res.SessionID}
	if code == CodeOK {
		claim.SessionIndex = sessionIndex
	}
	if err := writeSealed(conn, sess, ctrClaim, claim.marshal()); err != nil {
		if code == CodeOK {
			alloc.Rollback(vni, res)
		}
		return nil, fmt.Errorf("send ServerClaim: %w", err)
	}
	if code != CodeOK {
		return nil, fmt.Errorf("assign rejected: code=%d", code)
	}

	// wait for ack
	ackBytes, err := readSealed(conn, sess, ctrAck)
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

	// confirm (commit)
	alloc.Confirm(vni, res)

	return &protocol.SessionContext{
		SessionID:    res.SessionID,
		VNI:          vni,
		SessionIndex: sessionIndex,
		IP:           res.IP,
		IPRanges:     res.Ranges,
	}, nil
}

// ClientAssign runs the client side: receive the claimed IP + SessionID, accept
// it, and return the resulting SessionContext.
func ClientAssign(conn Conn, sess *noise.Session, vni protocol.VNI_Ty) (*protocol.SessionContext, error) {
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
		SessionID:    claim.SessionID,
		VNI:          vni,
		SessionIndex: claim.SessionIndex,
		IP:           claim.IP,
		IPRanges:     claim.Ranges,
	}, nil
}

// --------------- frames ---------------

// serverClaim: code(1) + sessionID(16) + sessionIndex(4) + ipLen(1) + ip
//   - rangeLen(1) + range + rangeBits(1)
type serverClaim struct {
	Code         Code
	SessionID    protocol.SessionID_Ty
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
