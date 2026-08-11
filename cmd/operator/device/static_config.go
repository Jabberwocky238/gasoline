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
	// VNI. Empty means "open" (test/bench). The Raft key table supersedes it
	// once consensus is wired into the handshake.
	AuthorizedKeys map[noise.PublicKey]struct{}
	PresetCIDmap   map[protocol.CID_Ty]netip.Prefix
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

	Network  map[protocol.VNI_Ty]StaticOperatorVNetConfig
	LogLevel logrus.Level
}

// ListenerSpec is a parsed '<schema>://<addr>' entry.
type ListenerSpec struct {
	Transport string
	Addr      string
}
