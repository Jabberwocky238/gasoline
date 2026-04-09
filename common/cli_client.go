package common

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"strconv"
)

// RegisterClientFlags registers all client CLI flags on the given FlagSet.
// Returns a function that resolves flags + config file into ClientConfig.
func RegisterClientFlags(fs *flag.FlagSet) func() *ClientConfig {
	configFile := fs.String("c", "", "config file path (YAML)")
	endpoint := fs.String("endpoint", "", "server address (required)")
	transportType := fs.String("transport", "quic", "transport type: tcp, udp, quic")
	authStr := fs.String("auth", "noauth", "auth config string")
	vnetIDStr := fs.String("vnet", "", "vnet ID (decimal number, e.g. 200)")
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
			if cfg.VNet != 0 && !isFlagSet(fs, "vnet") {
				*vnetIDStr = strconv.FormatUint(cfg.VNet, 10)
			}
			if cfg.TUNName != "" && !isFlagSet(fs, "tun-name") {
				*tunName = cfg.TUNName
			}
		}

		if *endpoint == "" {
			fmt.Fprintln(os.Stderr, "--endpoint is required")
			os.Exit(1)
		}

		var vnetID [16]byte
		if *vnetIDStr != "" {
			vnetNum, err := strconv.ParseUint(*vnetIDStr, 10, 64)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Invalid vnet ID %q: %v\n", *vnetIDStr, err)
				os.Exit(1)
			}
			binary.BigEndian.PutUint64(vnetID[8:], vnetNum)
		}

		if *socks5Port != 0 && *socks5Port <= 1024 {
			fmt.Fprintf(os.Stderr, "--quick-socks5 port must be > 1024, got %d\n", *socks5Port)
			os.Exit(1)
		}

		return &ClientConfig{
			Endpoint:   *endpoint,
			Transport:  *transportType,
			AuthStr:    *authStr,
			VNetID:     vnetID,
			TUNName:    *tunName,
			Socks5Port: *socks5Port,
		}
	}
}
