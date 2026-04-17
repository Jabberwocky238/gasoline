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
	opListen := fs.String("op-listen", "0.0.0.0:6677", "inter-operator bind address")
	opAddrClaim := fs.String("op-addr-claim", "", "address this operator claims to peers (host:port, public-reachable)")
	opAddrDiscover := fs.String("op-addr-discover", "", "seed operator addresses for discovery (comma-separated)")
	listenSpec := fs.String("listen", "quic://:8443", "client listeners: '<schema>://<addr>[;<schema>://<addr>...]', e.g. 'quic://:8080;tls://127.0.0.1:9000'")
	authStr := fs.String("auth", "noauth", "auth config string")
	network := fs.String("network", "0:10.0.0.0/24", "vnetID:CIDR pairs separated by ';'")
	statsAddr := fs.String("stats", "", "stats API listen address")
	watchDir := fs.String("watch-vni", "", "directory holding per-VNet config files (vni.d)")
	enableFswatch := fs.Bool("enable-fswatch", false, "enable inotify-based hot-reload of --watch-vni dir")
	enableSigreload := fs.Bool("enable-sigreload", false, "enable SIGHUP-triggered rescan of --watch-vni dir")
	enableK8s := fs.Bool("enable-k8s", false, "enable k8s VNetConfig informer hot-reload backend")
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
			if cfg.OpAddrClaim != "" && !isFlagSet(fs, "op-addr-claim") {
				*opAddrClaim = cfg.OpAddrClaim
			}
			if cfg.OpAddrDiscover != "" && !isFlagSet(fs, "op-addr-discover") {
				*opAddrDiscover = cfg.OpAddrDiscover
			}
			if cfg.Listen != "" && !isFlagSet(fs, "listen") {
				*listenSpec = cfg.Listen
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

		specs, err := ParseListenerSpecs(*listenSpec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Listen: %v\n", err)
			os.Exit(1)
		}

		result.ClientListeners = specs
		result.OpListenAddr = strings.TrimSpace(*opListen)
		result.OpExternalAddr = strings.TrimSpace(*opAddrClaim)
		if result.OpListenAddr == "" || result.OpExternalAddr == "" {
			fmt.Fprintf(os.Stderr, "op: --op-listen and --op-addr-claim must both be set (got op-listen=%q op-addr-claim=%q)\n",
				result.OpListenAddr, result.OpExternalAddr)
			os.Exit(1)
		}
		result.AuthStr = *authStr
		result.Network = *network
		result.StatsAddr = *statsAddr
		result.DiscoverAddrs = parseDiscoverAddrs(*opAddrDiscover)
		if len(result.DiscoverAddrs) == 0 {
			fmt.Fprintf(os.Stderr, "op: WARNING: --op-addr-discover is empty; this operator will only know peers that dial in\n")
		}
		result.WatchDir = *watchDir
		result.EnableFswatch = *enableFswatch
		result.EnableSigreload = *enableSigreload
		result.EnableK8s = *enableK8s
		// Namespace comes from the standard downward-API env var injected
		// on a gasoline-operator pod; kubeconfig is unset → in-cluster.
		result.K8sNamespace = os.Getenv("POD_NAMESPACE")
		if result.K8sNamespace == "" && result.EnableK8s {
			fmt.Fprintf(os.Stderr, "k8s: $POD_NAMESPACE env var must be set when --enable-k8s is true\n")
			os.Exit(1)
		}
		result.LogLevel = *logLevel
		return result
	}
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
