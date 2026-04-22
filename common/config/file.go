package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type FileConfig struct {
	Mode string `yaml:"mode"`

	Listen         string       `yaml:"listen"`
	OpListen       string       `yaml:"op-listen"`
	OpAddrClaim    string       `yaml:"op-addr-claim"`
	OpAddrDiscover string       `yaml:"op-addr-discover"`
	Network        []VnetConfig `yaml:"network"`
	StatsAddr      string       `yaml:"stats"`

	Endpoint  string `yaml:"endpoint"`
	VNet      uint64 `yaml:"vnet"`
	TUNName   string `yaml:"tun-name"`
	Transport string `yaml:"transport"`

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
