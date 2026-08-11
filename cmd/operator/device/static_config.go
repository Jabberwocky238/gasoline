package operator

import (
	"net/netip"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/sirupsen/logrus"
)

// StaticOperatorVNetConfig describes one VNI: '<vni>:<cidr>'.
type StaticOperatorVNetConfig struct {
	VNI          protocol.VNI_Ty
	CIDR         string
	Auth         auth.ServerAuthenticator
	PresetCIDmap map[protocol.CID_Ty]netip.Prefix
}

// StaticOperatorConfig is the resolved configuration handed to New.
// Construction is the binary's job (see cmd/operator); this package only
// owns the runtime types.
type StaticOperatorConfig struct {
	UUID            *[16]byte
	ClientListeners []ListenerSpec
	OpListenAddr    string

	Network  map[protocol.VNI_Ty]StaticOperatorVNetConfig
	LogLevel logrus.Level
}

// ListenerSpec is a parsed '<schema>://<addr>' entry.
type ListenerSpec struct {
	Transport string
	Addr      string
}
