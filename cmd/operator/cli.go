package operator

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/sirupsen/logrus"
)

// <vni>:<cidr>
type StaticOperatorVNetConfig struct {
	VNI  protocol.VNI_Ty
	CIDR string
	Auth auth.ServerAuthenticator
}

type StaticOperatorConfig struct {
	UUID            *[16]byte
	ClientListeners []ListenerSpec
	OpListenAddr    string // VXLAN UDP bind address ("host:port")
	OpExternalAddr  string // UDP endpoint claimed to the coordinator

	Network  map[protocol.VNI_Ty]StaticOperatorVNetConfig
	LogLevel logrus.Level
}

// RegisterOperatorFlags registers all operator CLI flags on the given FlagSet.
// Returns a function that resolves flags into StaticOperatorConfig.
func RegisterOperatorFlags(fs *flag.FlagSet) func() *StaticOperatorConfig {
	opListen := fs.String("op-listen", "0.0.0.0:6677", "VXLAN UDP data-plane bind address")
	opAddrClaim := fs.String("op-addr-claim", "", "UDP endpoint this operator claims to the coordinator (host:port, peer-reachable)")
	var listenSpec stringList
	fs.Var(&listenSpec, "listen", "client listener '<schema>://<addr>' (repeatable; default 'quic://:8443')")
	var network stringList
	fs.Var(&network, "network", "vnet entry '<vni>:<cidr>:<authtype>:[<auth>]' (repeatable; default '0:10.0.0.0/24:noauth:')")
	logLevel := fs.String("log-level", "info", "log level: trace, debug, info, warn, error")

	return func() *StaticOperatorConfig {
		result := &StaticOperatorConfig{
			Network: make(map[protocol.VNI_Ty]StaticOperatorVNetConfig),
		}

		listens := []string(listenSpec)
		if len(listens) == 0 {
			listens = []string{"quic://:8443"}
		}
		for _, raw := range listens {
			spec, err := parseListenerSpec(raw)
			if err != nil {
				fmt.Fprintf(os.Stderr, "listen: %v\n", err)
				os.Exit(1)
			}
			result.ClientListeners = append(result.ClientListeners, *spec)
		}

		result.OpListenAddr = strings.TrimSpace(*opListen)
		result.OpExternalAddr = strings.TrimSpace(*opAddrClaim)
		if result.OpListenAddr == "" || result.OpExternalAddr == "" {
			fmt.Fprintf(os.Stderr, "op: --op-listen and --op-addr-claim must both be set (got op-listen=%q op-addr-claim=%q)\n",
				result.OpListenAddr, result.OpExternalAddr)
			os.Exit(1)
		}

		entries := []string(network)
		if len(entries) == 0 {
			entries = []string{"0:10.0.0.0/24:noauth:"}
		}
		for _, raw := range entries {
			entryMap, err := parseNetworkEntry(raw, nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "network: %v\n", err)
				os.Exit(1)
			}
			for vni, entry := range entryMap {
				if _, dup := result.Network[vni]; dup {
					fmt.Fprintf(os.Stderr, "network: duplicate vni %d\n", vni)
					os.Exit(1)
				}
				result.Network[vni] = entry
			}
		}

		lvl, err := logrus.ParseLevel(strings.TrimSpace(*logLevel))
		if err != nil {
			fmt.Fprintf(os.Stderr, "log-level: %v\n", err)
			os.Exit(1)
		}
		result.LogLevel = lvl

		return result
	}
}

// stringList is a flag.Value that accumulates repeated occurrences.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// <vni>:<cidr>
func parseNetworkEntry(raw string, auth auth.ServerAuthenticator) (map[protocol.VNI_Ty]StaticOperatorVNetConfig, error) {
	out := make(map[protocol.VNI_Ty]StaticOperatorVNetConfig)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("network entry: empty")
	}
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("network entry %q: expected '<vni>:<cidr>'", raw)
	}
	vniU, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
	if err != nil {
		return nil, fmt.Errorf("network entry %q: invalid vni: %w", raw, err)
	}
	vni := protocol.VNI_Ty(vniU)
	cidr := strings.TrimSpace(parts[1])
	if cidr == "" {
		return nil, fmt.Errorf("network entry %q: empty cidr", raw)
	}
	out[vni] = StaticOperatorVNetConfig{
		VNI:  vni,
		CIDR: cidr,
		Auth: auth,
	}
	return out, nil
}

type ListenerSpec struct {
	Transport string
	Addr      string
}

// tcp://:8080
// quic://:8443
// tls://[::1]:9000
// udp://0.0.0.0:6677
func parseListenerSpec(raw string) (*ListenerSpec, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("listener spec %q: empty", raw)
	}
	schema, addr, ok := strings.Cut(raw, "://")
	if !ok {
		return nil, fmt.Errorf("listener spec %q: missing '://' separator (expected '<schema>://<addr>')", raw)
	}
	spec := ListenerSpec{
		Transport: strings.TrimSpace(schema),
		Addr:      strings.TrimSpace(addr),
	}
	if spec.Transport == "" {
		return nil, fmt.Errorf("listener spec %q: missing transport", raw)
	}
	switch spec.Transport {
	case "tcp", "udp", "quic", "tls":
	default:
		return nil, fmt.Errorf("listener spec %q: unsupported transport %q", raw, spec.Transport)
	}
	if spec.Addr == "" {
		return nil, fmt.Errorf("listener spec %q: missing bind addr", raw)
	}
	return &spec, nil
}
