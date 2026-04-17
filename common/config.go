package common

import (
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// --------------- YAML file config ---------------

// AuthConfig accepts both string ("hmac:id:secret") and structured YAML formats.
// After unmarshaling, String() always returns the canonical string format.
type AuthConfig struct {
	raw string // canonical string form
}

func (a *AuthConfig) String() string {
	if a == nil {
		return ""
	}
	return a.raw
}

func (a *AuthConfig) UnmarshalYAML(value *yaml.Node) error {
	// Case 1: plain string — "noauth", "hmac:id:secret;id2:secret2", etc.
	if value.Kind == yaml.ScalarNode {
		a.raw = value.Value
		return nil
	}

	// Case 2: structured array
	//   - type: hmac
	//     clients:
	//       - name: client1
	//         secret: mysecret
	if value.Kind == yaml.SequenceNode {
		var entries []authEntry
		if err := value.Decode(&entries); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
		if len(entries) == 0 {
			a.raw = "noauth"
			return nil
		}
		// Currently only the first entry is used (one auth type per vnet)
		a.raw = entries[0].toAuthString()
		return nil
	}

	return fmt.Errorf("auth: expected string or array, got %v", value.Kind)
}

type authEntry struct {
	Type    string       `yaml:"type"`
	Clients []authClient `yaml:"clients,omitempty"`
}

type authClient struct {
	Name     string `yaml:"name"`
	Secret   string `yaml:"secret,omitempty"`   // for hmac
	Password string `yaml:"password,omitempty"` // for userpass (plaintext or sha256 hex)
}

func (e *authEntry) toAuthString() string {
	switch e.Type {
	case "noauth", "":
		return "noauth"
	case "hmac":
		var parts []string
		for _, c := range e.Clients {
			parts = append(parts, c.Name+":"+c.Secret)
		}
		return "hmac:" + strings.Join(parts, ";")
	case "userpass":
		var parts []string
		for _, c := range e.Clients {
			parts = append(parts, c.Name+":"+c.Password)
		}
		return "userpass:" + strings.Join(parts, ";")
	default:
		return e.Type
	}
}

// NetworkEntry represents a single VNet:CIDR pair in the config file, with optional per-VNet auth.
type NetworkEntry struct {
	VNet uint64      `yaml:"vnet"`
	CIDR string      `yaml:"cidr"`
	Auth *AuthConfig `yaml:"auth,omitempty"`
}

// FileConfig holds all fields from the YAML config file.
type FileConfig struct {
	Mode string `yaml:"mode"` // "operator" or "client"

	// Operator fields
	Listen         string         `yaml:"listen"` // combined listener spec, e.g. "quic://:8080;tls://127.0.0.1:9000"
	OpListen       string         `yaml:"op-listen"`        // inter-operator bind address
	OpAddrClaim    string         `yaml:"op-addr-claim"`    // externally-advertised address
	OpAddrDiscover string         `yaml:"op-addr-discover"` // comma-separated seed addresses
	Network        []NetworkEntry `yaml:"network"`
	StatsAddr      string         `yaml:"stats"`

	// Client fields
	Endpoint  string `yaml:"endpoint"`
	VNet      uint64 `yaml:"vnet"`
	TUNName   string `yaml:"tun-name"`
	Transport string `yaml:"transport"` // client-only: transport kind (tcp/udp/quic/tls)

	// Shared fields
	Auth string `yaml:"auth"`
}

func LoadConfig(path string) (*FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg FileConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return &cfg, nil
}

func (c *FileConfig) NetworkString() string {
	parts := make([]string, len(c.Network))
	for i, n := range c.Network {
		parts[i] = fmt.Sprintf("%d:%s", n.VNet, n.CIDR)
	}
	return strings.Join(parts, ";")
}

// LoadVNetConfig parses a single vnet config YAML file (vnet + cidr + optional auth).
func LoadVNetConfig(path string) (*NetworkEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var entry NetworkEntry
	if err := yaml.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if entry.VNet == 0 || entry.CIDR == "" {
		return nil, fmt.Errorf("%s: missing vnet or cidr", path)
	}
	return &entry, nil
}

// --------------- Runtime configs ---------------

// ListenerSpec declares one client-facing listener: transport kind + bind addr.
type ListenerSpec struct {
	Transport string // "tcp", "udp", "quic", "tls"
	Addr      string // bind address, e.g. "0.0.0.0:8443"
}

// ParseListenerSpecs parses the combined transport flag, e.g.
//
//	"quic://:8080;tls://127.0.0.1:9000"
//
// into a slice of ListenerSpec. The input is first split on ';'; each entry
// is then split on "://" into (schema, addr). Both sides must be non-empty.
// Duplicate transports produce an error.
func ParseListenerSpecs(s string) ([]ListenerSpec, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty transport spec")
	}
	var out []ListenerSpec
	seen := make(map[string]struct{})
	for _, raw := range strings.Split(s, ";") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
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
		if _, dup := seen[spec.Transport]; dup {
			return nil, fmt.Errorf("duplicate transport %q", spec.Transport)
		}
		seen[spec.Transport] = struct{}{}
		out = append(out, spec)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no listener specs parsed from %q", s)
	}
	return out, nil
}

// OperatorConfig is the declarative configuration consumed by operator.New().
type OperatorConfig struct {
	UUID            *[16]byte      // optional: if nil, random UUID is generated
	ClientListeners []ListenerSpec // client-facing listeners (one per transport)
	OpListenAddr    string         // inter-operator bind address
	OpExternalAddr  string         // external address other operators use to reach us
	AuthStr         string         // global default auth string
	NetworkAuth     map[VNI]string // per-VNet auth overrides
	Network         string         // "vni:CIDR;..." pairs
	StatsAddr       string         // stats HTTP API address
	DiscoverAddrs   []string       // seed operator addresses for bootstrap
	WatchDir        string         // directory holding per-VNet config files (shared by fswatch + sigreload); "" = disabled
	EnableFswatch   bool           // enable the inotify-based directory hot-reload backend
	EnableSigreload bool           // enable the SIGHUP-triggered directory rescan backend
	EnableK8s       bool           // enable the k8s VNetConfig informer hot-reload backend
	K8sNamespace    string         // namespace for the k8s informer; resolved from $POD_NAMESPACE
	LogLevel        string         // log level: trace, debug, info, warn, error, fatal, panic
}

// ClientConfig is the declarative configuration consumed by client.New().
type ClientConfig struct {
	Endpoint   string // server address
	Transport  string // "tcp", "udp", "quic"
	AuthStr    string // auth config string
	VNI        VNI    // virtual network (24-bit VXLAN identifier)
	VMAC       VMAC   // 6-byte MAC-style forwarding identity
	TUNName    string // TUN device name
	Socks5Port int    // quick-socks5 port, 0 = disabled

	// Logger is the logrus logger injected by the caller. If nil, the client
	// falls back to logrus.StandardLogger(). Sub-components receive a derived
	// *logrus.Entry via context (see client.LoggerFrom).
	Logger *log.Logger
}
