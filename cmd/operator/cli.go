package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jabberwocky238/gasoline/device/operator"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/sirupsen/logrus"
)

// Recognized parameter keys for RegisterOperatorCLIParam.
//
//	op-listen   single-valued, host:port for the VXLAN UDP bind address
//	log-level   single-valued, trace|debug|info|warn|error
//	listen      repeatable,    '<schema>://<addr>' client listener
//	network     repeatable,    '<vni>:<cidr>' vnet entry
const (
	ParamOpListen = "op-listen"
	ParamLogLevel = "log-level"
	ParamListen   = "listen"
	ParamNetwork  = "network"
)

// RegisterOperatorCLIParam turns a parameter map (as produced by main.go's
// CLI parser) into a *operator.StaticOperatorConfig. Single-valued keys take
// the last entry of their slice; repeatable keys consume the whole slice.
// Missing keys fall back to documented defaults.
func RegisterOperatorCLIParam(params map[string][]string) (*operator.StaticOperatorConfig, error) {
	for k := range params {
		switch k {
		case ParamOpListen, ParamLogLevel, ParamListen, ParamNetwork:
		default:
			return nil, fmt.Errorf("unknown parameter %q", k)
		}
	}

	opListen := lastOr(params[ParamOpListen], "0.0.0.0:6677")
	logLevel := lastOr(params[ParamLogLevel], "info")

	listens := params[ParamListen]
	if len(listens) == 0 {
		listens = []string{"quic://:8443"}
	}
	nets := params[ParamNetwork]
	if len(nets) == 0 {
		nets = []string{"0:10.0.0.0/24"}
	}

	cfg := &operator.StaticOperatorConfig{
		Network: make(map[protocol.VNI_Ty]operator.StaticOperatorVNetConfig),
	}

	for _, raw := range listens {
		spec, err := parseListenerSpec(raw)
		if err != nil {
			return nil, err
		}
		cfg.ClientListeners = append(cfg.ClientListeners, spec)
	}

	cfg.OpListenAddr = strings.TrimSpace(opListen)

	for _, raw := range nets {
		entry, err := parseNetworkEntry(raw)
		if err != nil {
			return nil, err
		}
		if _, dup := cfg.Network[entry.VNI]; dup {
			return nil, fmt.Errorf("network: duplicate vni %d", entry.VNI)
		}
		cfg.Network[entry.VNI] = entry
	}

	lvl, err := logrus.ParseLevel(strings.TrimSpace(logLevel))
	if err != nil {
		return nil, fmt.Errorf("log-level: %w", err)
	}
	cfg.LogLevel = lvl

	return cfg, nil
}

func lastOr(vs []string, fallback string) string {
	if len(vs) == 0 {
		return fallback
	}
	return vs[len(vs)-1]
}

// parseNetworkEntry parses '<vni>:<cidr>'.
func parseNetworkEntry(raw string) (operator.StaticOperatorVNetConfig, error) {
	raw = strings.TrimSpace(raw)
	vniStr, cidr, ok := strings.Cut(raw, ":")
	if !ok {
		return operator.StaticOperatorVNetConfig{}, fmt.Errorf("network entry %q: expected '<vni>:<cidr>'", raw)
	}
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return operator.StaticOperatorVNetConfig{}, fmt.Errorf("network entry %q: empty cidr", raw)
	}
	vniU, err := strconv.ParseUint(strings.TrimSpace(vniStr), 10, 32)
	if err != nil {
		return operator.StaticOperatorVNetConfig{}, fmt.Errorf("network entry %q: invalid vni: %w", raw, err)
	}
	return operator.StaticOperatorVNetConfig{
		VNI:  protocol.VNI_Ty(vniU),
		CIDR: cidr,
	}, nil
}

// parseListenerSpec parses '<schema>://<addr>', e.g. 'quic://:8443'.
func parseListenerSpec(raw string) (operator.ListenerSpec, error) {
	raw = strings.TrimSpace(raw)
	schema, addr, ok := strings.Cut(raw, "://")
	if !ok {
		return operator.ListenerSpec{}, fmt.Errorf("listener %q: missing '://'", raw)
	}
	spec := operator.ListenerSpec{
		Transport: strings.TrimSpace(schema),
		Addr:      strings.TrimSpace(addr),
	}
	switch spec.Transport {
	case "tcp", "udp", "quic", "tls":
	case "":
		return operator.ListenerSpec{}, fmt.Errorf("listener %q: missing transport", raw)
	default:
		return operator.ListenerSpec{}, fmt.Errorf("listener %q: unsupported transport %q", raw, spec.Transport)
	}
	if spec.Addr == "" {
		return operator.ListenerSpec{}, fmt.Errorf("listener %q: missing addr", raw)
	}
	return spec, nil
}
