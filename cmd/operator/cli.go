package main

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/jabberwocky238/gasoline/device/operator"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/sirupsen/logrus"
)

// Recognized parameter keys for RegisterOperatorCLIParam.
//
//	op-listen   single-valued, host:port for the VXLAN UDP bind address
//	log-level   single-valued, trace|debug|info|warn|error
//	listen      repeatable,    '<schema>://<addr>' client listener
//	network     repeatable,    '<vni>:<cidr>:<authtype>[:<authdata>]' vnet entry
//	preset      repeatable,    '<vni>:<cid-hex>:<prefix>' preassigned cid->prefix
const (
	ParamOpListen = "op-listen"
	ParamLogLevel = "log-level"
	ParamListen   = "listen"
	ParamNetwork  = "network"
	ParamPreset   = "preset"
)

// RegisterOperatorCLIParam turns a parameter map (as produced by main.go's
// CLI parser) into a *operator.StaticOperatorConfig. Single-valued keys take
// the last entry of their slice; repeatable keys consume the whole slice.
// Missing keys fall back to documented defaults.
func RegisterOperatorCLIParam(params map[string][]string) (*operator.StaticOperatorConfig, error) {
	for k := range params {
		switch k {
		case ParamOpListen, ParamLogLevel, ParamListen, ParamNetwork, ParamPreset:
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
		nets = []string{"0:10.0.0.0/24:noauth"}
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
			return nil, fmt.Errorf("network: duplicate vni %s", entry.VNI)
		}
		cfg.Network[entry.VNI] = entry
	}

	// Attach preassigned cid->prefix bindings to their VNI's PresetCIDmap.
	presets := params[ParamPreset]
	if len(presets) == 0 {
		presets = []string{"0:100:10.0.0.1/32", "0:101:10.0.0.2/32", "0:102:10.0.0.3/32"}
	}
	for _, raw := range presets {
		vni, cid, pfx, err := parsePresetEntry(raw)
		if err != nil {
			return nil, err
		}
		entry, ok := cfg.Network[vni]
		if !ok {
			return nil, fmt.Errorf("preset %q: vni %d not declared via --network", raw, vni)
		}
		if entry.PresetCIDmap == nil {
			entry.PresetCIDmap = make(map[protocol.CID_Ty]netip.Prefix)
		}
		if existing, dup := entry.PresetCIDmap[cid]; dup && existing != pfx {
			return nil, fmt.Errorf("preset %q: cid %s already bound to %s", raw, cid.FormatCID(), existing)
		}
		entry.PresetCIDmap[cid] = pfx
		cfg.Network[vni] = entry
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

// parseNetworkEntry parses '<vni>:<cidr>:<authtype>[:<authdata>]'.
//
// authtype + authdata is forwarded to auth.ParseServerAuth as either
// "<authtype>" (e.g. "noauth") or "<authtype>:<authdata>" (e.g.
// "hmac:id:secret", "userpass:user:hash").
func parseNetworkEntry(raw string) (operator.StaticOperatorVNetConfig, error) {
	raw = strings.TrimSpace(raw)
	parts := strings.SplitN(raw, ":", 4)
	if len(parts) < 3 {
		return operator.StaticOperatorVNetConfig{}, fmt.Errorf("network entry %q: expected '<vni>:<cidr>:<authtype>[:<authdata>]'", raw)
	}
	vniU, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
	if err != nil {
		return operator.StaticOperatorVNetConfig{}, fmt.Errorf("network entry %q: invalid vni: %w", raw, err)
	}
	cidr := strings.TrimSpace(parts[1])
	if cidr == "" {
		return operator.StaticOperatorVNetConfig{}, fmt.Errorf("network entry %q: empty cidr", raw)
	}
	authType := strings.TrimSpace(parts[2])
	if authType == "" {
		return operator.StaticOperatorVNetConfig{}, fmt.Errorf("network entry %q: empty auth type", raw)
	}
	authSpec := authType
	if len(parts) == 4 {
		if rest := strings.TrimSpace(parts[3]); rest != "" {
			authSpec = authType + ":" + rest
		}
	}
	serverAuth, err := auth.ParseServerAuth(authSpec)
	if err != nil {
		return operator.StaticOperatorVNetConfig{}, fmt.Errorf("network entry %q: auth: %w", raw, err)
	}
	return operator.StaticOperatorVNetConfig{
		VNI:  protocol.VNI_Ty(vniU),
		CIDR: cidr,
		Auth: serverAuth,
	}, nil
}

// parsePresetEntry parses '<vni>:<cid>:<prefix>'. cid is decimal by
// default; prefix it with 0x for hex.
func parsePresetEntry(raw string) (protocol.VNI_Ty, protocol.CID_Ty, netip.Prefix, error) {
	var cid protocol.CID_Ty
	parts := strings.SplitN(strings.TrimSpace(raw), ":", 3)
	if len(parts) != 3 {
		return 0, cid, netip.Prefix{}, fmt.Errorf("preset %q: expected '<vni>:<cid>:<prefix>'", raw)
	}
	vniU, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
	if err != nil {
		return 0, cid, netip.Prefix{}, fmt.Errorf("preset %q: invalid vni: %w", raw, err)
	}
	cid, err = protocol.ParseCID(parts[1])
	if err != nil {
		return 0, cid, netip.Prefix{}, fmt.Errorf("preset %q: %w", raw, err)
	}
	pfx, err := netip.ParsePrefix(strings.TrimSpace(parts[2]))
	if err != nil {
		return 0, cid, netip.Prefix{}, fmt.Errorf("preset %q: invalid prefix: %w", raw, err)
	}
	return protocol.VNI_Ty(vniU), cid, pfx, nil
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
