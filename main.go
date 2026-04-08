package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/jabberwocky238/gasoline/client"
	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/operator"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport"
	"github.com/jabberwocky238/gasoline/transport/quic"
	"github.com/jabberwocky238/gasoline/transport/tcp"
	"github.com/jabberwocky238/gasoline/transport/udp"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	switch os.Args[1] {
	case "operator":
		runOperator(os.Args[2:])
	case "client":
		runClient(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  gasoline operator [flags]
  gasoline client   [flags]

Common flags:
  -c            Config file path (YAML, CLI flags override config values)

Operator flags:
  --listen      Client listen address (e.g. 0.0.0.0:443)
  --op-listen   Operator listen: <bind>;[external] (e.g. 0.0.0.0:6677;1.2.3.4:6677)
  --transport   Transport type: tcp, udp, quic (default: quic)
  --auth        Auth config (default: noauth)
                  noauth
                  hmac:<id>:<secret>;<id2>:<secret2>
                  userpass:<userid>:<sha256>;<userid2>:<sha256>
  --network     VNet:CIDR pairs (e.g. 200:10.0.0.0/24;1000:192.168.200.0/24)
  --stats       Stats API listen address (e.g. 127.0.0.1:9090)
  --discover    Seed operator addresses for auto-discovery (comma-separated)

Client flags:
  --endpoint    Server address (e.g. 1.2.3.4:443)
  --transport   Transport type: tcp, udp, quic (default: quic)
  --auth        Auth config (default: noauth)
                  noauth
                  hmac:<id>:<secret>
                  userpass:<userid>:<password>
  --vnet        VNet ID (decimal number, e.g. 200)
  --tun-name    TUN device name (default: empty, let sing-tun decide)
`)
	os.Exit(1)
}

// --------------- Operator ---------------

func runOperator(args []string) {
	fs := flag.NewFlagSet("operator", flag.ExitOnError)
	configFile := fs.String("c", "", "config file path (YAML)")
	listenAddr := fs.String("listen", "0.0.0.0:8443", "client listen address")
	opListen := fs.String("op-listen", "0.0.0.0:6677", "operator listen: <bind>;[external] (e.g. 0.0.0.0:6677;1.2.3.4:6677)")
	transportType := fs.String("transport", "quic", "transport type: tcp, udp, quic")
	authStr := fs.String("auth", "noauth", "auth config string")
	network := fs.String("network", "0:10.0.0.0/24", "vnetID:CIDR pairs separated by ';'")
	statsAddr := fs.String("stats", "127.0.0.1:9090", "stats API listen address (empty to disable)")
	discover := fs.String("discover", "", "seed operator addresses for discovery (comma-separated)")
	fs.Parse(args)

	// Load config file and apply as defaults (CLI flags override)
	if *configFile != "" {
		cfg, err := common.LoadConfig(*configFile)
		if err != nil {
			log.Fatalf("Config: %v", err)
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
	}

	// VNet pools
	pools, err := operator.ParseVNetPools(*network)
	if err != nil {
		log.Fatalf("Network: %v", err)
	}
	for vnetID, pool := range pools.All() {
		log.Infof("VNet %x: %s", vnetID, pool.Prefix)
	}

	// Server WG keypair
	serverPriv, err := protocol.NewPrivateKey()
	if err != nil {
		log.Fatalf("Generate server key: %v", err)
	}
	serverPub := serverPriv.PublicKey()
	log.Infof("Server public key: %s", serverPub.ToBase64())

	// Auth
	serverAuth, err := auth.ParseServerAuth(*authStr)
	if err != nil {
		log.Fatalf("Auth: %v", err)
	}

	// ConfigFunc
	configFn := operator.MakeConfigFunc(pools, serverPub, serverAuth)

	// Client listener
	clientListener, err := createListener(*transportType, *listenAddr, serverAuth, configFn)
	if err != nil {
		log.Fatalf("Listener: %v", err)
	}

	// Parse --op-listen: "<bind>;[external]"
	opListenAddr, opExternalAddr := parseOpListen(*opListen)

	// Parse discover seeds
	var discoverAddrs []string
	if *discover != "" {
		for _, addr := range strings.Split(*discover, ",") {
			addr = strings.TrimSpace(addr)
			if addr != "" {
				discoverAddrs = append(discoverAddrs, addr)
			}
		}
	}

	op := operator.New(&operator.Config{
		Auth:                serverAuth,
		ConfigFn:            configFn,
		ClientListener:      clientListener,
		OperatorListenAddr:  opListenAddr,
		OperatorExternalAddr: opExternalAddr,
		StatsAddr:           *statsAddr,
		DiscoverAddrs:       discoverAddrs,
	})

	if err := op.Start(); err != nil {
		log.Fatalf("Operator start: %v", err)
	}
	if opExternalAddr != "" {
		log.Infof("Operator started: client=%s (%s, %s), operator=%s (external %s)",
			*listenAddr, *transportType, serverAuth.Type(), opListenAddr, opExternalAddr)
	} else {
		log.Infof("Operator started: client=%s (%s, %s), operator=%s",
			*listenAddr, *transportType, serverAuth.Type(), opListenAddr)
	}
	waitForSignal()
	op.Close()
}

// --------------- Client ---------------

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	configFile := fs.String("c", "", "config file path (YAML)")
	endpoint := fs.String("endpoint", "", "server address (required)")
	transportType := fs.String("transport", "quic", "transport type: tcp, udp, quic")
	authStr := fs.String("auth", "noauth", "auth config string")
	vnetIDStr := fs.String("vnet", "", "vnet ID (decimal number, e.g. 200)")
	tunName := fs.String("tun-name", "", "TUN device name")
	fs.Parse(args)

	// Load config file and apply as defaults (CLI flags override)
	if *configFile != "" {
		cfg, err := common.LoadConfig(*configFile)
		if err != nil {
			log.Fatalf("Config: %v", err)
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
		log.Fatal("--endpoint is required")
	}

	// VNet ID
	var vnetID [16]byte
	if *vnetIDStr != "" {
		vnetNum, err := strconv.ParseUint(*vnetIDStr, 10, 64)
		if err != nil {
			log.Fatalf("Invalid vnet ID %q: %v", *vnetIDStr, err)
		}
		vnetID = common.EncodeVNetID(vnetNum)
	}

	// Auth
	clientAuth, err := auth.ParseClientAuth(*authStr, vnetID, []byte("default-fingerprint"))
	if err != nil {
		log.Fatalf("Auth: %v", err)
	}

	// SessionID (empty — server will assign via NoAuth)
	var sessionID [16]byte

	// Dialer
	dialer, err := createDialer(*transportType, sessionID, clientAuth)
	if err != nil {
		log.Fatalf("Dialer: %v", err)
	}

	c := client.New(&client.Config{
		Endpoint:  *endpoint,
		SessionID: sessionID,
		VNetID:    vnetID,
		TUNName:   *tunName,
		Dialer:    dialer,
	})

	if err := c.Start(); err != nil {
		log.Fatalf("Client start: %v", err)
	}
	log.Infof("Client connected to %s (%s, %s)", *endpoint, *transportType, clientAuth.Type())

	waitForSignal()
	c.Close()
}

// --------------- Transport factories ---------------

func createListener(transportType, addr string, serverAuth auth.ServerAuthenticator, configFn protocol.ConfigFunc) (transport.Listener, error) {
	switch transportType {
	case "tcp":
		return tcp.NewListener(addr, serverAuth, configFn)
	case "udp":
		return udp.NewListener(addr, serverAuth, configFn)
	case "quic":
		tlsConf, err := quic.GenerateServerTLS()
		if err != nil {
			return nil, err
		}
		return quic.NewListener(addr, serverAuth, configFn, tlsConf)
	default:
		return nil, fmt.Errorf("unknown transport: %s", transportType)
	}
}

func createDialer(transportType string, sessionID [16]byte, clientAuth auth.ClientAuthenticator) (transport.Dialer, error) {
	switch transportType {
	case "tcp":
		return tcp.NewDialer(sessionID, clientAuth), nil
	case "udp":
		return udp.NewDialer(sessionID, clientAuth), nil
	case "quic":
		return quic.NewDialer(sessionID, clientAuth, quic.InsecureClientTLS()), nil
	default:
		return nil, fmt.Errorf("unknown transport: %s", transportType)
	}
}

// --------------- Helpers ---------------

// parseOpListen splits "bind;external" into two addresses.
// If no ";", external is empty.
func parseOpListen(s string) (bind, external string) {
	parts := strings.SplitN(s, ";", 2)
	bind = strings.TrimSpace(parts[0])
	if len(parts) == 2 {
		external = strings.TrimSpace(parts[1])
	}
	return
}

// isFlagSet checks if a flag was explicitly set on the command line.
func isFlagSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func waitForSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	<-sigs
	log.Info("Shutting down...")
}

