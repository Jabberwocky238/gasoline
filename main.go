package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/jabberwocky238/gasoline/client"
	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/operator"
	"github.com/jabberwocky238/gasoline/protocol"
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

Operator flags:
  --listen      Client listen address (e.g. 0.0.0.0:443)
  --op-listen   Operator listen address (e.g. 0.0.0.0:6677)
  --transport   Transport type: tcp, udp, quic (default: quic)
  --auth        Auth type: noauth, hmac, userpass (default: noauth)
  --network     VNet:CIDR pairs (e.g. 200:10.0.0.0/24;1000:192.168.200.0/24)
  --secret      Shared secret for HMAC auth

Client flags:
  --endpoint    Server address (e.g. 1.2.3.4:443)
  --transport   Transport type: tcp, udp, quic (default: quic)
  --auth        Auth type: noauth, hmac, userpass (default: noauth)
  --vnet        VNet ID (decimal number, e.g. 200)
  --tun-name    TUN device name (default: empty, let sing-tun decide)
  --secret      Shared secret for HMAC auth
  --username    Username for userpass auth
  --password    Password for userpass auth
`)
	os.Exit(1)
}

// --------------- Operator ---------------

func runOperator(args []string) {
	fs := flag.NewFlagSet("operator", flag.ExitOnError)
	listenAddr := fs.String("listen", "0.0.0.0:8443", "client listen address")
	opListenAddr := fs.String("op-listen", "0.0.0.0:6677", "operator listen address")
	transportType := fs.String("transport", "quic", "transport type: tcp, udp, quic")
	authType := fs.String("auth", "noauth", "auth type: noauth, hmac, userpass")
	network := fs.String("network", "0:10.0.0.0/24", "vnetID:CIDR pairs separated by ';'")
	secret := fs.String("secret", "", "shared secret for HMAC auth")
	fs.Parse(args)

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
	serverAuth, err := protocol.NewServerAuth(*authType, *secret)
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

	op := operator.New(&operator.Config{
		Auth:               serverAuth,
		ConfigFn:           configFn,
		ClientListener:     clientListener,
		OperatorListenAddr: *opListenAddr,
	})

	if err := op.Start(); err != nil {
		log.Fatalf("Operator start: %v", err)
	}
	log.Infof("Operator started: client=%s (%s, %s), operator=%s",
		*listenAddr, *transportType, *authType, *opListenAddr)
	waitForSignal()
	op.Close()
}

// --------------- Client ---------------

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	endpoint := fs.String("endpoint", "", "server address (required)")
	transportType := fs.String("transport", "quic", "transport type: tcp, udp, quic")
	authType := fs.String("auth", "noauth", "auth type: noauth, hmac, userpass")
	vnetIDStr := fs.String("vnet", "", "vnet ID (decimal number, e.g. 200)")
	tunName := fs.String("tun-name", "", "TUN device name")
	secret := fs.String("secret", "", "shared secret for HMAC auth")
	username := fs.String("username", "", "username for userpass auth")
	password := fs.String("password", "", "password for userpass auth")
	fs.Parse(args)

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
	var clientAuth protocol.ClientAuthenticator
	if *authType == "noauth" {
		clientAuth = &protocol.NoAuthClient{
			VNetID:      vnetID,
			Fingerprint: []byte("default-fingerprint"), // TODO: real device fingerprint
		}
	} else {
		var err error
		clientAuth, err = protocol.NewClientAuth(*authType, *secret, *username, *password)
		if err != nil {
			log.Fatalf("Auth: %v", err)
		}
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
	log.Infof("Client connected to %s (%s, %s)", *endpoint, *transportType, *authType)

	waitForSignal()
	c.Close()
}

// --------------- Transport factories ---------------

func createListener(transportType, addr string, auth protocol.ServerAuthenticator, configFn protocol.ConfigFunc) (transport.Listener, error) {
	switch transportType {
	case "tcp":
		return tcp.NewListener(addr, auth, configFn)
	case "udp":
		return udp.NewListener(addr, auth, configFn)
	case "quic":
		tlsConf, err := quic.GenerateServerTLS()
		if err != nil {
			return nil, err
		}
		_ = tlsConf // TODO: uncomment when quic-go is added
		return nil, fmt.Errorf("QUIC transport not yet available (quic-go dependency needed)")
		// return quic.NewListener(addr, auth, configFn, tlsConf)
	default:
		return nil, fmt.Errorf("unknown transport: %s", transportType)
	}
}

func createDialer(transportType string, sessionID [16]byte, auth protocol.ClientAuthenticator) (transport.Dialer, error) {
	switch transportType {
	case "tcp":
		return tcp.NewDialer(sessionID, auth), nil
	case "udp":
		return udp.NewDialer(sessionID, auth), nil
	case "quic":
		_ = quic.InsecureClientTLS() // TODO: uncomment when quic-go is added
		return nil, fmt.Errorf("QUIC transport not yet available (quic-go dependency needed)")
		// return quic.NewDialer(sessionID, auth, quic.InsecureClientTLS()), nil
	default:
		return nil, fmt.Errorf("unknown transport: %s", transportType)
	}
}

// --------------- Helpers ---------------

func waitForSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	<-sigs
	log.Info("Shutting down...")
}

