package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/jabberwocky238/gasoline/client"
	"github.com/jabberwocky238/gasoline/operator"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/transport"
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
  --transport   Transport type: tcp, udp (default: tcp)
  --auth        Auth type: noauth, hmac, userpass (default: noauth)
  --network     Internal network CIDR (e.g. 10.0.0.0/24)
  --secret      Shared secret for HMAC auth

Client flags:
  --endpoint    Server address (e.g. 1.2.3.4:443)
  --transport   Transport type: tcp, udp (default: tcp)
  --auth        Auth type: noauth, hmac, userpass (default: noauth)
  --session     Session ID in hex (max 32 hex chars = 16 bytes)
  --vnet        VNet ID in hex (max 32 hex chars = 16 bytes)
  --secret      Shared secret for HMAC auth
  --username    Username for userpass auth
  --password    Password for userpass auth
`)
	os.Exit(1)
}

// --------------- Operator ---------------

func runOperator(args []string) {
	fs := flag.NewFlagSet("operator", flag.ExitOnError)
	listenAddr := fs.String("listen", "0.0.0.0:443", "client listen address")
	opListenAddr := fs.String("op-listen", "0.0.0.0:6677", "operator listen address")
	transportType := fs.String("transport", "tcp", "transport type: tcp, udp")
	authType := fs.String("auth", "noauth", "auth type: noauth, hmac, userpass")
	network := fs.String("network", "10.0.0.0/24", "internal network CIDR")
	secret := fs.String("secret", "", "shared secret for HMAC auth")
	fs.Parse(args)

	// Parse network
	prefix, err := netip.ParsePrefix(*network)
	if err != nil {
		log.Fatalf("Invalid network: %v", err)
	}

	// Server WG keypair
	serverPriv, err := protocol.NewPrivateKey()
	if err != nil {
		log.Fatalf("Generate server key: %v", err)
	}
	serverPub := serverPriv.PublicKey()
	log.Infof("Server public key: %s", serverPub.ToBase64())

	// IP allocator: base address + counter
	// e.g. 10.0.0.0/24 → clients get 10.0.0.2/32, 10.0.0.3/32, ...
	baseAddr := prefix.Addr()
	var ipCounter atomic.Uint32
	ipCounter.Store(2) // .0 = network, .1 = reserved for operator/gateway

	// Auth
	serverAuth := makeServerAuth(*authType, *secret)

	// ConfigFunc: allocate IP + generate client WG key + assign session ID
	configFn := func(clientID [16]byte) (*protocol.SessionConfig, error) {
		seq := ipCounter.Add(1) - 1
		clientIP := addToAddr(baseAddr, seq)
		if !prefix.Contains(clientIP) {
			return nil, fmt.Errorf("IP pool exhausted")
		}

		clientPriv, err := protocol.NewPrivateKey()
		if err != nil {
			return nil, err
		}

		// Get session ID from NoAuth server if applicable
		var sessionID [16]byte
		if noauth, ok := serverAuth.(*protocol.NoAuthServer); ok {
			sessionID = noauth.LastSessionID
		}

		return &protocol.SessionConfig{
			SessionID:        sessionID,
			ClientPrivateKey: clientPriv,
			ServerPublicKey:  serverPub,
			IPPrefix:         netip.PrefixFrom(clientIP, 32),
			AllowedRanges:    []netip.Prefix{prefix},
		}, nil
	}

	// Create client listener
	var clientListener transport.Listener
	switch *transportType {
	case "tcp":
		l, err := tcp.NewListener(*listenAddr, serverAuth, configFn)
		if err != nil {
			log.Fatalf("TCP listen: %v", err)
		}
		clientListener = l
	case "udp":
		l, err := udp.NewListener(*listenAddr, serverAuth, configFn)
		if err != nil {
			log.Fatalf("UDP listen: %v", err)
		}
		clientListener = l
	default:
		log.Fatalf("Unknown transport: %s", *transportType)
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
	log.Infof("Operator started: client=%s (%s, %s), operator=%s, network=%s",
		*listenAddr, *transportType, *authType, *opListenAddr, *network)
	waitForSignal()
	op.Close()
}

// --------------- Client ---------------

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	endpoint := fs.String("endpoint", "", "server address (required)")
	transportType := fs.String("transport", "tcp", "transport type: tcp, udp")
	authType := fs.String("auth", "noauth", "auth type: noauth, hmac, userpass")
	sessionIDHex := fs.String("session", "", "session ID in hex (max 32 hex chars)")
	vnetIDHex := fs.String("vnet", "", "vnet ID in hex (max 32 hex chars)")
	secret := fs.String("secret", "", "shared secret for HMAC auth")
	username := fs.String("username", "", "username for userpass auth")
	password := fs.String("password", "", "password for userpass auth")
	fs.Parse(args)

	if *endpoint == "" {
		log.Fatal("--endpoint is required")
	}

	// Parse session ID and vnet ID
	var sessionID [16]byte
	if *sessionIDHex != "" {
		b, err := hex.DecodeString(*sessionIDHex)
		if err != nil {
			log.Fatalf("Invalid session ID hex: %v", err)
		}
		copy(sessionID[:], b)
	}
	var vnetID [16]byte
	if *vnetIDHex != "" {
		b, err := hex.DecodeString(*vnetIDHex)
		if err != nil {
			log.Fatalf("Invalid vnet ID hex: %v", err)
		}
		copy(vnetID[:], b)
	}

	// Auth
	var clientAuth protocol.ClientAuthenticator
	if *authType == "noauth" {
		clientAuth = &protocol.NoAuthClient{
			VNetID:      vnetID,
			Fingerprint: []byte("default-fingerprint"), // TODO: real device fingerprint
		}
	} else {
		clientAuth = makeClientAuth(*authType, *secret, *username, *password)
	}

	// Dialer
	var cfg *client.Config
	switch *transportType {
	case "tcp":
		cfg = &client.Config{
			Endpoint:  *endpoint,
			SessionID: sessionID,
			VNetID:    vnetID,
			Dialer:    tcp.NewDialer(sessionID, clientAuth),
		}
	case "udp":
		cfg = &client.Config{
			Endpoint:  *endpoint,
			SessionID: sessionID,
			VNetID:    vnetID,
			Dialer:    udp.NewDialer(sessionID, clientAuth),
		}
	default:
		log.Fatalf("Unknown transport: %s", *transportType)
	}

	c := client.New(cfg)
	if err := c.Start(); err != nil {
		log.Fatalf("Client start: %v", err)
	}
	log.Infof("Client connected to %s (%s, %s)", *endpoint, *transportType, *authType)

	waitForSignal()
	c.Close()
}

// --------------- Helpers ---------------

func makeServerAuth(authType, secret string) protocol.ServerAuthenticator {
	switch authType {
	case "noauth":
		return &protocol.NoAuthServer{}
	case "hmac":
		if secret == "" {
			log.Fatal("HMAC auth requires --secret")
		}
		secretBytes := []byte(secret)
		return &protocol.HMACAuthServer{
			LookupSecret: func(clientID [16]byte) ([]byte, error) {
				return secretBytes, nil
			},
		}
	case "userpass":
		// Simple in-memory store; extend as needed
		var mu sync.RWMutex
		users := map[string]string{
			"admin": "admin",
		}
		return &protocol.UserPassAuthServer{
			LookupPassword: func(username string) (string, error) {
				mu.RLock()
				defer mu.RUnlock()
				pass, ok := users[username]
				if !ok {
					return "", fmt.Errorf("unknown user: %s", username)
				}
				return pass, nil
			},
		}
	default:
		log.Fatalf("Unknown auth type: %s", authType)
		return nil
	}
}

func makeClientAuth(authType, secret, username, password string) protocol.ClientAuthenticator {
	switch authType {
	case "noauth":
		return &protocol.NoAuthClient{}
	case "hmac":
		if secret == "" {
			log.Fatal("HMAC auth requires --secret")
		}
		return &protocol.HMACAuthClient{Secret: []byte(secret)}
	case "userpass":
		if username == "" || password == "" {
			log.Fatal("UserPass auth requires --username and --password")
		}
		return &protocol.UserPassAuthClient{Username: username, Password: password}
	default:
		log.Fatalf("Unknown auth type: %s", authType)
		return nil
	}
}

// addToAddr adds an offset to a netip.Addr (IPv4 only for simplicity).
func addToAddr(base netip.Addr, offset uint32) netip.Addr {
	b4 := base.As4()
	val := uint32(b4[0])<<24 | uint32(b4[1])<<16 | uint32(b4[2])<<8 | uint32(b4[3])
	val += offset
	return netip.AddrFrom4([4]byte{
		byte(val >> 24), byte(val >> 16), byte(val >> 8), byte(val),
	})
}

func waitForSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	<-sigs
	log.Info("Shutting down...")
}
