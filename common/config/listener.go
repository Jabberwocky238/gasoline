package config

import (
	"fmt"
	"strings"
)

type ListenerSpec struct {
	Transport string
	Addr      string
}

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
