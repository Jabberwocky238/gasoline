package config

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type AuthConfig struct {
	raw string
}

func (a *AuthConfig) String() string {
	if a == nil {
		return ""
	}
	return a.raw
}

func (a *AuthConfig) UnmarshalYAML(value *yaml.Node) error {
	if value == nil || value.Tag == "!!null" {
		a.raw = ""
		return nil
	}
	if value.Kind == yaml.ScalarNode {
		a.raw = strings.TrimSpace(value.Value)
		return nil
	}
	if value.Kind == yaml.SequenceNode {
		var entries []authEntry
		if err := value.Decode(&entries); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
		if len(entries) == 0 {
			a.raw = "noauth"
		} else {
			a.raw = entries[0].toAuthString()
		}
		return nil
	}
	return fmt.Errorf("auth: expected string or array, got %v", value.Kind)
}

func (a *AuthConfig) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		a.raw = ""
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		a.raw = strings.TrimSpace(s)
		return nil
	}
	var entries []authEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("auth: expected string or array: %w", err)
	}
	if len(entries) == 0 {
		a.raw = "noauth"
	} else {
		a.raw = entries[0].toAuthString()
	}
	return nil
}

type authEntry struct {
	Type    string       `yaml:"type,omitempty" json:"type,omitempty"`
	Clients []authClient `yaml:"clients,omitempty" json:"clients,omitempty"`
}

type authClient struct {
	Name     string `yaml:"name,omitempty" json:"name,omitempty"`
	Secret   string `yaml:"secret,omitempty" json:"secret,omitempty"`
	Password string `yaml:"password,omitempty" json:"password,omitempty"`
}

func (e *authEntry) toAuthString() string {
	t := strings.ToLower(strings.TrimSpace(e.Type))
	switch t {
	case "", "noauth":
		return "noauth"
	case "hmac":
		parts := make([]string, 0, len(e.Clients))
		for _, c := range e.Clients {
			name := strings.TrimSpace(c.Name)
			if name == "" {
				continue
			}
			parts = append(parts, name+":"+strings.TrimSpace(c.Secret))
		}
		if len(parts) == 0 {
			return "noauth"
		}
		return "hmac:" + strings.Join(parts, ";")
	case "userpass":
		parts := make([]string, 0, len(e.Clients))
		for _, c := range e.Clients {
			name := strings.TrimSpace(c.Name)
			if name == "" {
				continue
			}
			parts = append(parts, name+":"+strings.TrimSpace(c.Password))
		}
		if len(parts) == 0 {
			return "noauth"
		}
		return "userpass:" + strings.Join(parts, ";")
	default:
		return t
	}
}
