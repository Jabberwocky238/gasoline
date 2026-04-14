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
	clientIDStr := fs.String("client-id", "", "6-byte MAC-style client ID, e.g. 02:00:00:aa:bb:cc (random if empty)")
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

		var vni VNI
		if *vniStr != "" {
			parsed, err := ParseVNI(*vniStr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Invalid VNI %q: %v\n", *vniStr, err)
				os.Exit(1)
			}
			vni = parsed
		}

		if *socks5Port != 0 && *socks5Port <= 1024 {
			fmt.Fprintf(os.Stderr, "--quick-socks5 port must be > 1024, got %d\n", *socks5Port)
			os.Exit(1)
		}

		cid, err := resolveClientID(*clientIDStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid --client-id %q: %v\n", *clientIDStr, err)
			os.Exit(1)
		}

		return &ClientConfig{
			Endpoint:   *endpoint,
			Transport:  *transportType,
			AuthStr:    *authStr,
			VNI:        vni,
			ClientID:   cid,
			TUNName:    *tunName,
			Socks5Port: *socks5Port,
		}
	}
}

// resolveClientID parses a MAC-formatted client ID (e.g. "02:00:00:aa:bb:cc"
// or "020000aabbcc") or generates a random one if empty.
func resolveClientID(s string) (ClientID, error) {
	var cid ClientID
	if s == "" {
		if _, err := rand.Read(cid[:]); err != nil {
			return cid, err
		}
		cid[0] = (cid[0] & 0xFE) | 0x02 // unicast + locally-administered
		return cid, nil
	}
	hexStr := strings.ReplaceAll(strings.ReplaceAll(s, ":", ""), "-", "")
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return cid, err
	}
	if len(b) != ClientIDLen {
		return cid, fmt.Errorf("must be %d bytes, got %d", ClientIDLen, len(b))
	}
	copy(cid[:], b)
	return cid, nil
}
