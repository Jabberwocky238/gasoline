package common

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// RegisterOperatorFlags registers all operator CLI flags on the given FlagSet.
// Returns a function that resolves flags + config file into OperatorConfig.
func RegisterOperatorFlags(fs *flag.FlagSet) func() *OperatorConfig {
	configFile := fs.String("c", "", "config file path (YAML)")
	opListen := fs.String("op-listen", "0.0.0.0:6677", "operator listen: <bind>;[external]")
	transportType := fs.String("transport", "quic://:8443", "client listeners: '<schema>://<addr>[;<schema>://<addr>...]', e.g. 'quic://:8080;tls://127.0.0.1:9000'")
	authStr := fs.String("auth", "noauth", "auth config string")
	network := fs.String("network", "0:10.0.0.0/24", "vnetID:CIDR pairs separated by ';'")
	statsAddr := fs.String("stats", "", "stats API listen address")
	discover := fs.String("discover", "", "seed operator addresses for discovery (comma-separated)")
	watchDir := fs.String("watch", "", "directory to watch for vnet config files")
	logLevel := fs.String("log-level", "info", "log level: trace, debug, info, warn, error")

	return func() *OperatorConfig {
		result := &OperatorConfig{
			NetworkAuth: make(map[VNI]string),
		}

		if *configFile != "" {
			cfg, err := LoadConfig(*configFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Config: %v\n", err)
				os.Exit(1)
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
				if entry.Auth != nil && entry.Auth.String() != "" {
					vni := VNI(entry.VNet)
					if vni.Valid() {
						result.NetworkAuth[vni] = entry.Auth.String()
					}
				}
			}
		}

		// Parse op-listen: "bind;external"
		opListenAddr, opExternalAddr := parseOpListen(*opListen)

		specs, err := ParseListenerSpecs(*transportType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Transport: %v\n", err)
			os.Exit(1)
		}

		result.ClientListeners = specs
		result.OpListenAddr = opListenAddr
		result.OpExternalAddr = opExternalAddr
		result.AuthStr = *authStr
		result.Network = *network
		result.StatsAddr = *statsAddr
		result.DiscoverAddrs = parseDiscoverAddrs(*discover)
		result.WatchDir = *watchDir
		result.LogLevel = *logLevel
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
