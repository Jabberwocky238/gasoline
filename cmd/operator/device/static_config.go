package operator

import (
	"net/netip"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/noise"
	"github.com/sirupsen/logrus"
)

// StaticOperatorVNetConfig describes one VNI: '<vni>:<cidr>'.
type StaticOperatorVNetConfig struct {
	VNI  protocol.VNI_Ty
	CIDR string
	// AuthorizedKeys is the set of client static public keys allowed on this
	// VNI. A key not in the set is rejected. The Raft key table supersedes it
	// once consensus is wired into the handshake.
	AuthorizedKeys map[noise.PublicKey]struct{}
	// PresetKeyMap statically pins a public key to a fixed IP (the fixed-IP /
	// lock semantics of PRD §4.5). At handshake the pinned IP is handed out and
	// the routing table binds sessionID -> prefix. Empty entries fall through to
	// dynamic pool allocation (P4).
	PresetKeyMap map[noise.PublicKey]netip.Prefix
}

// StaticOperatorConfig is the resolved configuration handed to New.
// Construction is the binary's job (see cmd/operator); this package only
// owns the runtime types.
type StaticOperatorConfig struct {
	UUID            *[16]byte
	ClientListeners []ListenerSpec
	OpListenAddr    string

	// StaticPriv is the operator's Noise static private key. If zero, New
	// generates a fresh pair (its public key must then be conveyed to clients
	// out of band, same as WireGuard).
	StaticPriv noise.PrivateKey

	// Raft, when non-nil, enables the consensus-backed IP/SessionID allocator.
	// nil leaves the operator on the pre-consensus preset allocator.
	Raft *RaftConfig

	Network  map[protocol.VNI_Ty]StaticOperatorVNetConfig
	LogLevel logrus.Level

	// HopEndpoints is the authoritative list of hop targets advertised to
	// clients at assignment (PRD §6.2). Each entry is one operator's host + the
	// UDP port ranges it accepts data frames on. Empty means "no hopping
	// advertised" — the client stays on its handshake endpoint.
	HopEndpoints []HopEndpoint
}

// HopEndpoint describes one advertisable hop target: an operator's UUID, host,
// and the inclusive UDP port ranges it listens on.
type HopEndpoint struct {
	UUID  [16]byte
	Host  string      // IP literal
	Ports [][2]uint16 // inclusive [lo, hi] ranges
}

// RaftConfig is the parsed --raft-* configuration for the consensus layer.
type RaftConfig struct {
	// LocalID is this node's stable Raft ID (defaults to the operator UUID hex).
	LocalID string
	// BindAddr is the QUIC address this node's Raft transport listens on.
	BindAddr string
	// Peers is the initial cluster membership ("id@host:port" entries).
	Peers []RaftPeer
	// Bootstrap seeds a brand-new cluster from Peers. Set on exactly one node.
	Bootstrap bool
}

// RaftPeer names one cluster member.
type RaftPeer struct {
	ID   string
	Addr string
}

// ListenerSpec is a parsed '<schema>://<addr>' entry.
type ListenerSpec struct {
	Transport string
	Addr      string
}
