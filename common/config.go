package common

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// --------------- YAML file config ---------------

// NetworkEntry represents a single VNet:CIDR pair in the config file, with optional per-VNet auth.
type NetworkEntry struct {
	VNet uint64 `yaml:"vnet"`
	CIDR string `yaml:"cidr"`
	Auth string `yaml:"auth,omitempty"`
}

// FileConfig holds all fields from the YAML config file.
type FileConfig struct {
	Mode string `yaml:"mode"` // "operator" or "client"

	// Operator fields
	Listen    string         `yaml:"listen"`
	OpListen  string         `yaml:"op-listen"`
	Network   []NetworkEntry `yaml:"network"`
	StatsAddr string         `yaml:"stats"`

	// Client fields
	Endpoint string `yaml:"endpoint"`
	VNet     uint64 `yaml:"vnet"`
	TUNName  string `yaml:"tun-name"`

	// Shared fields
	Transport string `yaml:"transport"`
	Auth      string `yaml:"auth"`
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

// --------------- Runtime configs ---------------

// OperatorConfig is the declarative configuration consumed by operator.New().
type OperatorConfig struct {
	UUID           *[16]byte           // optional: if nil, random UUID is generated
	ListenAddr     string              // client listen address
	OpListenAddr   string              // inter-operator bind address
	OpExternalAddr string              // external address other operators use to reach us
	Transport      string              // "tcp", "udp", "quic"
	AuthStr        string              // global default auth string
	NetworkAuth    map[[16]byte]string  // per-VNet auth overrides
	Network        string              // "vnetID:CIDR;..." pairs
	StatsAddr      string              // stats HTTP API address
	DiscoverAddrs  []string            // seed operator addresses for bootstrap
}

// ClientConfig is the declarative configuration consumed by client.New().
type ClientConfig struct {
	Endpoint    string   // server address
	Transport   string   // "tcp", "udp", "quic"
	AuthStr     string   // auth config string
	VNetID      [16]byte // virtual network ID
	TUNName     string   // TUN device name
	Socks5Port  int      // quick-socks5 port, 0 = disabled
}
