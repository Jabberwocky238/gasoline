package common

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// NetworkEntry represents a single VNet:CIDR pair in the config file.
type NetworkEntry struct {
	VNet uint64 `yaml:"vnet"`
	CIDR string `yaml:"cidr"`
}

// Config holds all configuration fields shared by operator and client.
type Config struct {
	Mode string `yaml:"mode"` // "operator" or "client"

	// Operator fields
	Listen   string         `yaml:"listen"`
	OpListen string         `yaml:"op-listen"`
	Network  []NetworkEntry `yaml:"network"`

	// Client fields
	Endpoint string `yaml:"endpoint"`
	VNet     uint64 `yaml:"vnet"`
	TUNName  string `yaml:"tun-name"`

	// Shared fields
	Transport string `yaml:"transport"`
	Auth      string `yaml:"auth"` // "noauth", "hmac:id:secret", "userpass:user:password"
}

// LoadConfig reads and parses a YAML config file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return &cfg, nil
}

// NetworkString converts the Network entries to the CLI format "vnet:CIDR;vnet:CIDR".
func (c *Config) NetworkString() string {
	parts := make([]string, len(c.Network))
	for i, n := range c.Network {
		parts[i] = fmt.Sprintf("%d:%s", n.VNet, n.CIDR)
	}
	return strings.Join(parts, ";")
}
