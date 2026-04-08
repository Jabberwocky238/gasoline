package common

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"strings"
)

// RegisterOperatorFlags registers all operator CLI flags on the given FlagSet.
// Returns a function that resolves flags + config file into OperatorConfig.
func RegisterOperatorFlags(fs *flag.FlagSet) func() *OperatorConfig {
	configFile := fs.String("c", "", "config file path (YAML)")
	listenAddr := fs.String("listen", "0.0.0.0:8443", "client listen address")
	opListen := fs.String("op-listen", "0.0.0.0:6677", "operator listen: <bind>;[external]")
	transportType := fs.String("transport", "quic", "transport type: tcp, udp, quic")
	authStr := fs.String("auth", "noauth", "auth config string")
	network := fs.String("network", "0:10.0.0.0/24", "vnetID:CIDR pairs separated by ';'")
	statsAddr := fs.String("stats", "127.0.0.1:9090", "stats API listen address")
	discover := fs.String("discover", "", "seed operator addresses for discovery (comma-separated)")

	return func() *OperatorConfig {
		result := &OperatorConfig{
			NetworkAuth: make(map[[16]byte]string),
		}

		if *configFile != "" {
			cfg, err := LoadConfig(*configFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Config: %v\n", err)
				os.Exit(1)
			}
			if cfg.Listen != "" && !isFlagSet(fs, "listen") {
				*listenAddr = cfg.Listen
			}
			if cfg.OpListen != "" && !isFlagSet(fs, "op-listen") {
				*opListen = cfg.OpListen
			}
			if cfg.Transport != "" && !isFlagSet(fs, "transport") {
				*transportType = cfg.Transport
			}
			if cfg.Auth != "" && !isFlagSet(fs, "auth") {
				*authStr = cfg.Auth
			}
			if len(cfg.Network) > 0 && !isFlagSet(fs, "network") {
				*network = cfg.NetworkString()
			}
			if cfg.StatsAddr != "" && !isFlagSet(fs, "stats") {
				*statsAddr = cfg.StatsAddr
			}
			for _, entry := range cfg.Network {
				if entry.Auth != "" {
					var vnetID [16]byte
					binary.BigEndian.PutUint64(vnetID[8:], entry.VNet)
					result.NetworkAuth[vnetID] = entry.Auth
				}
			}
		}

		// Parse op-listen: "bind;external"
		opListenAddr, opExternalAddr := parseOpListen(*opListen)

		result.ListenAddr = *listenAddr
		result.OpListenAddr = opListenAddr
		result.OpExternalAddr = opExternalAddr
		result.Transport = *transportType
		result.AuthStr = *authStr
		result.Network = *network
		result.StatsAddr = *statsAddr
		result.DiscoverAddrs = parseDiscoverAddrs(*discover)
		return result
	}
}

func parseOpListen(s string) (bind, external string) {
	parts := strings.SplitN(s, ";", 2)
	bind = strings.TrimSpace(parts[0])
	if len(parts) == 2 {
		external = strings.TrimSpace(parts[1])
	}
	return
}

func parseDiscoverAddrs(s string) []string {
	if s == "" {
		return nil
	}
	var addrs []string
	for _, addr := range strings.Split(s, ",") {
		addr = strings.TrimSpace(addr)
		if addr != "" {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}
