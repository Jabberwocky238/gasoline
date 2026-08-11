// Package consensus provides the operator-side strong-consistency layer:
// a hashicorp/raft state machine (meshState / FSM) replicated over a QUIC
// transport. Every operator holds a full replica of the mesh control state
// (vnets, segments, IP pools, key grants, sessions, access-point location),
// so a client that hops to any operator is served identically.
//
// This is the control plane only. The data plane (IP-packet forwarding
// between operators) stays on the direct UDP underlay and never touches
// Raft — see PRD §2.5.
package consensus

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net/netip"
	"time"

	"github.com/jabberwocky238/gasoline/protocol"
)

// CmdKind discriminates the Raft log entry type. One command per kind.
type CmdKind uint8

const (
	CmdUnknown        CmdKind = 0x00
	CmdVNetUpsert     CmdKind = 0x01 // add/replace a vnet definition (segments, pools)
	CmdKeyGrant       CmdKind = 0x10 // authorize a pubkey on a vnet
	CmdKeyRevoke      CmdKind = 0x11 // deauthorize a pubkey (cascades to its sessions)
	CmdSessionCreate  CmdKind = 0x20 // handshake: allocate ip + session
	CmdSessionRenew   CmdKind = 0x21 // keepalive: refresh lease (batched)
	CmdSessionMigrate CmdKind = 0x22 // access-point changed (batched)
	CmdSessionDrop    CmdKind = 0x23 // remove a session (timeout / kick / revoke)
	CmdSessionReplace CmdKind = 0x24 // atomic drop-old + create-new for one pubkey
	CmdBatch          CmdKind = 0xF0 // envelope carrying N commands, applied in order
)

// Command is one Raft log entry. Exactly one of the payload pointers is
// non-nil, selected by Kind. Batch carries a slice of sub-commands.
//
// Encoding is gob: this is a control plane, correctness and evolvability
// matter more than bytes on the wire.
type Command struct {
	Kind CmdKind

	VNetUpsert     *VNetUpsert
	KeyGrant       *KeyGrant
	KeyRevoke      *KeyRevoke
	SessionCreate  *SessionCreate
	SessionRenew   *SessionRenew
	SessionMigrate *SessionMigrate
	SessionDrop    *SessionDrop
	SessionReplace *SessionReplace
	Batch          []Command
}

// --------------- command payloads ---------------

// VNetUpsert adds or replaces a vnet definition. Pool ⊆ CIDR is validated
// at apply time (PRD §2.2); a violation rejects the whole command.
type VNetUpsert struct {
	VNI      protocol.VNI_Ty
	Segments []Segment
}

// Segment is one subnet within a vnet plus its allocatable pool.
type Segment struct {
	CIDR     netip.Prefix
	Pool     netip.Prefix // must be a subset of CIDR
	Reserved []netip.Addr // gateway etc., never handed out
}

// KeyGrant authorizes a static pubkey on a vnet, optionally pinning an IP.
type KeyGrant struct {
	VNI        protocol.VNI_Ty
	PubKey     [32]byte
	AllowedSeg []netip.Prefix // segments this key may draw an address from
	StaticIP   netip.Addr     // optional fixed binding (invalid = none)
}

// KeyRevoke deauthorizes a pubkey; Apply cascades a drop of its sessions.
type KeyRevoke struct {
	VNI    protocol.VNI_Ty
	PubKey [32]byte
}

// SessionCreate is the single Raft write a handshake performs (PRD §2.3).
type SessionCreate struct {
	SessionID protocol.SessionID_Ty
	PubKey    [32]byte
	VNI       protocol.VNI_Ty
	IP        netip.Addr // pre-selected by the admitting operator
	HopSecret [32]byte
	Operator  [16]byte // owner at creation time
	LeaseTTL  time.Duration
	Now       int64 // unix nanos, supplied by proposer (FSM must be deterministic)
}

// SessionRenew refreshes a lease (keepalive; batched — PRD §4.3).
type SessionRenew struct {
	SessionID protocol.SessionID_Ty
	Now       int64
	LeaseTTL  time.Duration
}

// SessionMigrate records a new access point (batched — PRD §6.3).
type SessionMigrate struct {
	SessionID protocol.SessionID_Ty
	Operator  [16]byte
	Now       int64
}

// DropReason mirrors the PRD's kick/timeout taxonomy.
type DropReason uint8

const (
	DropTimeout DropReason = iota
	DropKicked
	DropRevoked
	DropReplaced
)

// SessionDrop removes a session and frees its (non-pinned) IP.
type SessionDrop struct {
	SessionID protocol.SessionID_Ty
	Reason    DropReason
}

// SessionReplace atomically removes any existing session for PubKey and
// creates a new one (PRD §8.0.2). Keeps a pinned IP if one exists.
type SessionReplace struct {
	New SessionCreate
}

// --------------- encode / decode ---------------

// Encode serializes a Command for raft.Apply.
func (c *Command) Encode() ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(c); err != nil {
		return nil, fmt.Errorf("consensus: encode: %w", err)
	}
	return buf.Bytes(), nil
}

// DecodeCommand parses a Raft log entry back into a Command.
func DecodeCommand(b []byte) (*Command, error) {
	var c Command
	if err := gob.NewDecoder(bytes.NewReader(b)).Decode(&c); err != nil {
		return nil, fmt.Errorf("consensus: decode: %w", err)
	}
	return &c, nil
}
