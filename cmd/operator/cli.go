package main

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/jabberwocky238/gasoline/cmd/operator/device"
	"github.com/jabberwocky238/gasoline/protocol/noise"
	"github.com/sirupsen/logrus"
)

// Recognized parameter keys for RegisterOperatorCLIParam.
//
//	op-listen   single-valued, host:port for the VXLAN UDP bind address
//	log-level   single-valued, trace|debug|info|warn|error
//	key         single-valued, operator static private key (base64); generated if empty
//	listen      repeatable,    '<schema>://<addr>' client listener
//	network     repeatable,    '<vni>:<cidr>[:<pubkey_b64>,...]' vnet entry
//	raft-bind   single-valued, this node's Raft QUIC listen address
//	raft-peers  single-valued, 'id@host:port;id2@host:port2' cluster members
//	raft-bootstrap single-valued, "true" on exactly one node to seed the cluster
const (
	ParamOpListen      = "op-listen"
	ParamLogLevel      = "log-level"
	ParamKey           = "key" // operator static private key (base64); generated if empty
	ParamListen        = "listen"
	ParamRoot          = "root" // config dir: one YAML per vnet, fsnotify-watched (PRD §4.4)
	ParamRaftBind      = "raft-bind"
	ParamRaftPeers     = "raft-peers"
	ParamRaftBootstrap = "raft-bootstrap"
)

// RegisterOperatorCLIParam turns a parameter map (as produced by main.go's
// CLI parser) into a *operator.StaticOperatorConfig. Single-valued keys take
// the last entry of their slice; repeatable keys consume the whole slice.
// Missing keys fall back to documented defaults.
func RegisterOperatorCLIParam(params map[string][]string) (*operator.StaticOperatorConfig, error) {
	for k := range params {
		switch k {
		case ParamOpListen, ParamLogLevel, ParamKey, ParamListen, ParamRoot,
			ParamRaftBind, ParamRaftPeers, ParamRaftBootstrap:
		default:
			return nil, fmt.Errorf("unknown parameter %q", k)
		}
	}

	opListen := lastOr(params[ParamOpListen], "0.0.0.0:6677")
	logLevel := lastOr(params[ParamLogLevel], "info")

	// A persistent identity must be supplied: clients encrypt their
	// Noise_IK initiation to this key, so regenerating it on every
	// restart invalidates every client's configuration.
	var staticPriv noise.PrivateKey
	if s := strings.TrimSpace(lastOr(params[ParamKey], "")); s != "" {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("key: invalid base64: %w", err)
		}
		staticPriv, err = noise.PrivateKeyFromSlice(b)
		if err != nil {
			return nil, fmt.Errorf("key: %w", err)
		}
	}

	listens := params[ParamListen]
	if len(listens) == 0 {
		listens = []string{"quic://:8443"}
	}

	cfg := &operator.StaticOperatorConfig{
		StaticPriv: staticPriv,
		RootDir:    strings.TrimSpace(lastOr(params[ParamRoot], "")),
	}

	for _, raw := range listens {
		spec, err := parseListenerSpec(raw)
		if err != nil {
			return nil, err
		}
		cfg.ClientListeners = append(cfg.ClientListeners, spec)
	}

	cfg.OpListenAddr = strings.TrimSpace(opListen)

	// vnet definitions (segments/pool/keys, incl. fixed-IP bindings) come from
	// the --root config dir (PRD §4.4), loaded + fsnotify-watched at runtime —
	// not from the command line.

	// Consensus (Raft) — enabled iff --raft-bind is given.
	if bind := strings.TrimSpace(lastOr(params[ParamRaftBind], "")); bind != "" {
		rc, err := parseRaftConfig(bind, lastOr(params[ParamRaftPeers], ""), lastOr(params[ParamRaftBootstrap], ""))
		if err != nil {
			return nil, err
		}
		cfg.Raft = rc
	}

	lvl, err := logrus.ParseLevel(strings.TrimSpace(logLevel))
	if err != nil {
		return nil, fmt.Errorf("log-level: %w", err)
	}
	cfg.LogLevel = lvl

	return cfg, nil
}

// parseRaftConfig builds a RaftConfig from the --raft-* params. peers is a
// ';'-separated list of 'id@host:port'. bootstrap is "true"/"1" to seed.
func parseRaftConfig(bind, peers, bootstrap string) (*operator.RaftConfig, error) {
	rc := &operator.RaftConfig{BindAddr: strings.TrimSpace(bind)}
	switch strings.TrimSpace(bootstrap) {
	case "", "false", "0":
	case "true", "1":
		rc.Bootstrap = true
	default:
		return nil, fmt.Errorf("raft-bootstrap %q: want true|false", bootstrap)
	}
	for _, entry := range strings.Split(peers, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, addr, ok := strings.Cut(entry, "@")
		if !ok {
			return nil, fmt.Errorf("raft-peers %q: expected 'id@host:port'", entry)
		}
		rc.Peers = append(rc.Peers, operator.RaftPeer{ID: strings.TrimSpace(id), Addr: strings.TrimSpace(addr)})
	}
	if rc.Bootstrap && len(rc.Peers) == 0 {
		return nil, fmt.Errorf("raft-bootstrap requires --raft-peers")
	}
	return rc, nil
}

func lastOr(vs []string, fallback string) string {
	if len(vs) == 0 {
		return fallback
	}
	return vs[len(vs)-1]
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
	case "udp", "quic":
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
