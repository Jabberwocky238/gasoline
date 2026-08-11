package protocol

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sync"
)

type VNI_Ty uint32 // 24-bit virtual network identifier (VNI), stored in a uint32 for convenience

// String renders a VNI as both decimal and hex, e.g. "1234 (0x04d2)".
func (vni VNI_Ty) String() string {
	return fmt.Sprintf("%d (0x%06x)", uint32(vni), uint32(vni))
}

// SessionID_Ty is the cluster-unique session identifier — the equivalent of
// WireGuard's receiver index, but allocated via Raft 2PC (not per-machine) so
// it stays consistent across every PE. It is the data-plane decryption key
// (which session / which keypair) AND the routing key (RouteTargetClient names
// a session, not a client identity). There is no CID.
type SessionID_Ty [16]byte

// String renders a SessionID as hex.
func (s SessionID_Ty) String() string { return hex.EncodeToString(s[:]) }

// IsZero reports whether the SessionID is unset.
func (s SessionID_Ty) IsZero() bool {
	for _, b := range s {
		if b != 0 {
			return false
		}
	}
	return true
}

// NewSessionID mints a random 16-byte SessionID. In the Raft path the value is
// proposed by the admitting PE and committed by consensus; this generator is
// the source of that proposal (and is used directly in the pre-Raft local
// path).
func NewSessionID() SessionID_Ty {
	var s SessionID_Ty
	_, _ = rand.Read(s[:])
	return s
}

// HopPortRange is an inclusive UDP port interval a hop target accepts traffic on.
type HopPortRange struct {
	Lo uint16
	Hi uint16
}

// HopServer is one operator a client may send data frames to after the
// handshake (PRD §6.2). The client picks a random (server, port-in-range) each
// hop interval. Populated from the authoritative list in the assignment's
// confirm frame.
type HopServer struct {
	UUID  [16]byte
	Host  netip.Addr
	Ports []HopPortRange
}

type SessionContext struct {
	mu sync.RWMutex

	SessionID    SessionID_Ty // cluster-unique session id (routing + decryption key)
	VNI          VNI_Ty       // 24-bit virtual network identifier
	SessionIndex uint32       // local session index for logging / packet headers
	IP           netip.Addr   // Client's assigned IP (e.g. 10.0.0.2)
	IPRanges     netip.Prefix // Internal network ranges routable via VPN (e.g. 10.0.0.0/24)
	servers      []HopServer  // hop targets from the assignment (guarded by mu)
}

// SetServers replaces the hop-target list (called once at assignment).
func (sc *SessionContext) SetServers(s []HopServer) {
	sc.mu.Lock()
	sc.servers = s
	sc.mu.Unlock()
}

// Servers returns a copy of the hop-target list.
func (sc *SessionContext) Servers() []HopServer {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return append([]HopServer(nil), sc.servers...)
}

func (sc *SessionContext) Copy() SessionContext {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return SessionContext{
		SessionID:    sc.SessionID,
		VNI:          sc.VNI,
		SessionIndex: sc.SessionIndex,
		IP:           sc.IP,
		IPRanges:     sc.IPRanges,
		servers:      append([]HopServer(nil), sc.servers...),
	}
}

// PresetSessionConfig is the VNI the client knows up-front (from its config)
// and ships in ClientHello. The rest of SessionContext is filled in by the
// server during handshake + assignment.
type PresetSessionConfig struct {
	VNI VNI_Ty
}

func NewPresetSessionConfig(vni VNI_Ty) PresetSessionConfig {
	return PresetSessionConfig{VNI: vni}
}
