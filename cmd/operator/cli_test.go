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

	if len(cfg.Network) != 1 {
		t.Fatalf("Network len = %d, want 1", len(cfg.Network))
	}
	entry, ok := cfg.Network[0]
	if !ok {
		t.Fatalf("Network missing vni 0: %+v", cfg.Network)
	}
	if entry.CIDR != "10.0.0.0/24" {
		t.Errorf("default cidr = %q, want 10.0.0.0/24", entry.CIDR)
	}
}

func TestRegisterOperatorCLIParam_RepeatedListenAndNetwork(t *testing.T) {
	cfg, err := RegisterOperatorCLIParam(map[string][]string{
		"listen":  {"udp://127.0.0.1:1000", "quic://127.0.0.1:2000"},
		"network": {"1:10.1.0.0/16:noauth", "2:10.2.0.0/16:noauth"},
		// Override the VNI-0 preset defaults; this case declares 1 and 2.
		"preset": {"1:100:10.1.0.1/32", "2:101:10.2.0.1/32"},
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

	if len(cfg.Network) != 2 {
		t.Fatalf("Network len = %d, want 2", len(cfg.Network))
	}
	if cfg.Network[1].CIDR != "10.1.0.0/16" || cfg.Network[2].CIDR != "10.2.0.0/16" {
		t.Errorf("network = %+v", cfg.Network)
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

func TestRegisterOperatorCLIParam_DuplicateVNI(t *testing.T) {
	_, err := RegisterOperatorCLIParam(map[string][]string{
		"network": {"5:10.5.0.0/16:noauth", "5:10.6.0.0/16:noauth"},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate vni") {
		t.Fatalf("err = %v, want duplicate vni error", err)
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

func TestParseNetworkEntry(t *testing.T) {
	t.Run("noauth", func(t *testing.T) {
		got, err := parseNetworkEntry("7:10.7.0.0/24:noauth")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if got.VNI != 7 || got.CIDR != "10.7.0.0/24" || got.Auth == nil {
			t.Errorf("got %+v", got)
		}
	})
	t.Run("hmac", func(t *testing.T) {
		got, err := parseNetworkEntry("7:10.7.0.0/24:hmac:id1:secret1")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if got.VNI != 7 || got.CIDR != "10.7.0.0/24" || got.Auth == nil {
			t.Errorf("got %+v", got)
		}
	})

	cases := map[string]string{
		"missing auth":      "7:10.7.0.0/24",
		"only vni":          "abc",
		"bad vni":           "x:10.0.0.0/24:noauth",
		"empty cidr":        "1::noauth",
		"empty auth type":   "1:10.0.0.0/24:",
		"unknown auth type": "1:10.0.0.0/24:bogus:",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseNetworkEntry(in); err == nil {
				t.Fatalf("expected error for %q", in)
			}
		})
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
