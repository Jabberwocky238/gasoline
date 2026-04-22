package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type VnetConfig struct {
	VNet       uint64      `yaml:"vnet" json:"vnet"`
	CIDR       string      `yaml:"cidr" json:"cidr"`
	Auth       *AuthConfig `yaml:"auth,omitempty" json:"auth,omitempty"`
	AnycastIPs []string    `yaml:"anycast_ips,omitempty" json:"anycast_ips,omitempty"`
}

func LoadVNetConfig(path string) (*VnetConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var entry VnetConfig
	if err := yaml.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if entry.VNet == 0 || entry.CIDR == "" {
		return nil, fmt.Errorf("%s: missing vnet or cidr", path)
	}
	return &entry, nil
}
