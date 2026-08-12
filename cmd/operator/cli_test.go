package main

import (
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestRegisterOperatorCLIParam_Defaults(t *testing.T) {
	cfg, err := RegisterOperatorCLIParam(nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if cfg.OpListenAddr != "0.0.0.0:6677" {
		t.Errorf("OpListenAddr = %q, want 0.0.0.0:6677", cfg.OpListenAddr)
	}
	if cfg.LogLevel != logrus.InfoLevel {
		t.Errorf("LogLevel = %v, want info", cfg.LogLevel)
	}

	if len(cfg.ClientListeners) != 1 {
		t.Fatalf("ClientListeners len = %d, want 1", len(cfg.ClientListeners))
	}
	if got := cfg.ClientListeners[0]; got.Transport != "quic" || got.Addr != ":8443" {
		t.Errorf("default listener = %+v, want {quic :8443}", got)
	}

	// vnets come from --root, not the CLI: no default vnet is seeded.
	if len(cfg.Network) != 0 {
		t.Errorf("Network should be empty (vnets via --root), got %d", len(cfg.Network))
	}
	if cfg.RootDir != "" {
		t.Errorf("RootDir default = %q, want empty", cfg.RootDir)
	}
}

func TestRegisterOperatorCLIParam_RepeatedListenAndRoot(t *testing.T) {
	cfg, err := RegisterOperatorCLIParam(map[string][]string{
		"listen": {"udp://127.0.0.1:1000", "quic://127.0.0.1:2000"},
		"root":   {"/etc/gasoline/vnets"},
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if len(cfg.ClientListeners) != 2 {
		t.Fatalf("ClientListeners len = %d, want 2", len(cfg.ClientListeners))
	}
	if cfg.ClientListeners[0].Transport != "udp" || cfg.ClientListeners[1].Transport != "quic" {
		t.Errorf("listeners = %+v", cfg.ClientListeners)
	}
	if cfg.RootDir != "/etc/gasoline/vnets" {
		t.Errorf("RootDir = %q, want /etc/gasoline/vnets", cfg.RootDir)
	}
}

func TestRegisterOperatorCLIParam_SingleValuedTakesLast(t *testing.T) {
	cfg, err := RegisterOperatorCLIParam(map[string][]string{
		"op-listen": {"a:1", "b:2"},
		"log-level": {"info", "debug"},
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if cfg.OpListenAddr != "b:2" {
		t.Errorf("OpListenAddr = %q, want b:2", cfg.OpListenAddr)
	}
	if cfg.LogLevel != logrus.DebugLevel {
		t.Errorf("LogLevel = %v, want debug", cfg.LogLevel)
	}
}

func TestRegisterOperatorCLIParam_BadLogLevel(t *testing.T) {
	_, err := RegisterOperatorCLIParam(map[string][]string{
		"log-level": {"wat"},
	})
	if err == nil || !strings.Contains(err.Error(), "log-level") {
		t.Fatalf("err = %v, want log-level error", err)
	}
}

func TestRegisterOperatorCLIParam_UnknownKey(t *testing.T) {
	_, err := RegisterOperatorCLIParam(map[string][]string{
		"bogus": {"x"},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown parameter") {
		t.Fatalf("err = %v, want unknown parameter error", err)
	}
}

func TestParseListenerSpec(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		got, err := parseListenerSpec("quic://[::1]:9000")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if got.Transport != "quic" || got.Addr != "[::1]:9000" {
			t.Errorf("got %+v", got)
		}
	})

	cases := map[string]string{
		"missing sep":   "quic:8443",
		"bad transport": "sctp://:8443",
		"empty addr":    "quic://",
		"empty schema":  "://:8443",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseListenerSpec(in); err == nil {
				t.Fatalf("expected error for %q", in)
			}
		})
	}
}

func TestRegisterOperatorCLIParam_Raft(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		cfg, err := RegisterOperatorCLIParam(nil)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if cfg.Raft != nil {
			t.Errorf("Raft should be nil without --raft-bind")
		}
	})

	t.Run("bootstrap cluster", func(t *testing.T) {
		cfg, err := RegisterOperatorCLIParam(map[string][]string{
			"raft-bind":      {"127.0.0.1:7000"},
			"raft-peers":     {"a@127.0.0.1:7000;b@127.0.0.1:7001"},
			"raft-bootstrap": {"true"},
		})
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if cfg.Raft == nil {
			t.Fatal("Raft should be set")
		}
		if cfg.Raft.BindAddr != "127.0.0.1:7000" || !cfg.Raft.Bootstrap {
			t.Errorf("raft = %+v", cfg.Raft)
		}
		if len(cfg.Raft.Peers) != 2 || cfg.Raft.Peers[0].ID != "a" || cfg.Raft.Peers[1].Addr != "127.0.0.1:7001" {
			t.Errorf("peers = %+v", cfg.Raft.Peers)
		}
	})

	cases := map[string]map[string][]string{
		"bootstrap without peers": {"raft-bind": {"127.0.0.1:7000"}, "raft-bootstrap": {"true"}},
		"bad peer format":         {"raft-bind": {"127.0.0.1:7000"}, "raft-peers": {"noatsign"}},
		"bad bootstrap value":     {"raft-bind": {"127.0.0.1:7000"}, "raft-bootstrap": {"maybe"}},
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := RegisterOperatorCLIParam(params); err == nil {
				t.Fatalf("expected error for %v", params)
			}
		})
	}
}
