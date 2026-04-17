package common

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// RegisterClientFlags registers all client CLI flags on the given FlagSet.
// Returns a function that resolves flags + config file into ClientConfig.
func RegisterClientFlags(fs *flag.FlagSet) func() *ClientConfig {
	configFile := fs.String("c", "", "config file path (YAML)")
	endpoint := fs.String("endpoint", "", "server address (required)")
	transportType := fs.String("transport", "quic", "transport type: tcp, udp, quic")
	authStr := fs.String("auth", "noauth", "auth config string")
	vniStr := fs.String("vni", "", "VXLAN Network Identifier (decimal, e.g. 200)")
	vmacStr := fs.String("vmac", "", "6-byte virtual MAC, e.g. 02:00:00:aa:bb:cc (random if empty)")
	tunName := fs.String("tun-name", "", "TUN device name")
	socks5Port := fs.Int("quick-socks5", 0, "SOCKS5 proxy port (0=disabled, must be >1024)")

	return func() *ClientConfig {
		if *configFile != "" {
			cfg, err := LoadConfig(*configFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Config: %v\n", err)
				os.Exit(1)
			}
			if cfg.Endpoint != "" && !isFlagSet(fs, "endpoint") {
				*endpoint = cfg.Endpoint
			}
			if cfg.Transport != "" && !isFlagSet(fs, "transport") {
				*transportType = cfg.Transport
			}
			if cfg.Auth != "" && !isFlagSet(fs, "auth") {
				*authStr = cfg.Auth
			}
			if cfg.VNet != 0 && !isFlagSet(fs, "vni") {
				*vniStr = strconv.FormatUint(cfg.VNet, 10)
			}
			if cfg.TUNName != "" && !isFlagSet(fs, "tun-name") {
				*tunName = cfg.TUNName
			}
		}

		if *endpoint == "" {
			fmt.Fprintln(os.Stderr, "--endpoint is required")
			os.Exit(1)
		}

		if *vniStr == "" {
			fmt.Fprintln(os.Stderr, "--vni is required (must match one of the operator's configured VNIs)")
			os.Exit(1)
		}
		vni, err := ParseVNI(*vniStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid VNI %q: %v\n", *vniStr, err)
			os.Exit(1)
		}
		if vni == 0 {
			fmt.Fprintln(os.Stderr, "--vni must be non-zero")
			os.Exit(1)
		}

		if *socks5Port != 0 && *socks5Port <= 1024 {
			fmt.Fprintf(os.Stderr, "--quick-socks5 port must be > 1024, got %d\n", *socks5Port)
			os.Exit(1)
		}

		vmac, err := resolveVMAC(*vmacStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid --vmac %q: %v\n", *vmacStr, err)
			os.Exit(1)
		}
		if (vmac == VMAC{}) {
			fmt.Fprintln(os.Stderr, "--vmac must be non-zero (omit the flag to auto-generate one)")
			os.Exit(1)
		}

		return &ClientConfig{
			Endpoint:   *endpoint,
			Transport:  *transportType,
			AuthStr:    *authStr,
			VNI:        vni,
			VMAC:       vmac,
			TUNName:    *tunName,
			Socks5Port: *socks5Port,
		}
	}
}

// resolveVMAC parses a MAC-formatted address (e.g. "02:00:00:aa:bb:cc"
// or "020000aabbcc") or generates a random locally-administered one if empty.
func resolveVMAC(s string) (VMAC, error) {
	var v VMAC
	if s == "" {
		if _, err := rand.Read(v[:]); err != nil {
			return v, err
		}
		v[0] = (v[0] & 0xFE) | 0x02 // unicast + locally-administered
		return v, nil
	}
	hexStr := strings.ReplaceAll(strings.ReplaceAll(s, ":", ""), "-", "")
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return v, err
	}
	if len(b) != VMACLen {
		return v, fmt.Errorf("must be %d bytes, got %d", VMACLen, len(b))
	}
	copy(v[:], b)
	return v, nil
}
