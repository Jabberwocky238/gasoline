package main

import (
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

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
		fmt.Fprintf(os.Stderr, "Usage: gasoline <operator|client> [flags]\n")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "operator":
		runOperator(os.Args[2:])
	case "client":
		runClient(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Usage: gasoline <operator|client> [flags]\n")
		os.Exit(1)
	}
}

// --------------- Operator ---------------

func runOperator(args []string) {
	fs := flag.NewFlagSet("operator", flag.ExitOnError)
	resolve := common.RegisterOperatorFlags(fs)
	fs.Parse(args)
	a := resolve()

	// VNet pools
	pools, err := operator.ParseVNetPools(a.Network, rand.Uint32())
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

	// Build per-VNet AuthResolver
	defaultAuth, err := auth.ParseServerAuth(a.AuthStr)
	if err != nil {
		log.Fatalf("Auth: %v", err)
	}
	resolver := auth.NewMapResolver(defaultAuth)
	for vnetID, authStr := range a.NetworkAuth {
		vnetAuth, err := auth.ParseServerAuth(authStr)
		if err != nil {
			log.Fatalf("Auth for vnet %x: %v", vnetID, err)
		}
		resolver.Set(vnetID, vnetAuth)
		log.Infof("VNet %x: auth=%s", vnetID, vnetAuth.Type())
	}

	// ConfigFunc — allocates IPs from VNet pool
	configFn := func(clientID [16]byte, vnetID [16]byte) (*protocol.SessionConfig, error) {
		pool, ok := pools.Get(operator.VNetIDType(vnetID))
		if !ok {
			return nil, fmt.Errorf("unknown vnet %x", vnetID)
		}
		clientIP, err := pool.AllocateIP()
		if err != nil {
			return nil, err
		}
		clientPriv, err := protocol.NewPrivateKey()
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		h.Write(clientID[:])
		var ts [8]byte
		binary.BigEndian.PutUint64(ts[:], uint64(time.Now().UnixNano()))
		h.Write(ts[:])
		var sessionID [16]byte
		copy(sessionID[:], h.Sum(nil)[:16])
		return &protocol.SessionConfig{
			SessionID:        sessionID,
			VNetID:           vnetID,
			ClientPrivateKey: clientPriv,
			ServerPublicKey:  serverPub,
			IPPrefix:         netip.PrefixFrom(clientIP, 32),
			AllowedRanges:    []netip.Prefix{pool.Prefix},
		}, nil
	}

	// Client listener
	clientListener, err := createListener(a.Transport, a.ListenAddr, resolver, configFn)
	if err != nil {
		log.Fatalf("Listener: %v", err)
	}

	// Operator identity
	opListenAddr, opExternalAddr := a.OpListenAddrs()
	var opUUID operator.OperatorUUIDType
	cryptoRand.Read(opUUID[:])

	op := operator.New(&operator.Config{
		UUID:                 opUUID,
		Auth:                 resolver,
		ConfigFn:             configFn,
		ClientListener:       clientListener,
		OperatorListenAddr:   opListenAddr,
		OperatorExternalAddr: opExternalAddr,
		StatsAddr:            a.StatsAddr,
		DiscoverAddrs:        a.DiscoverAddrs(),
	})
	log.Infof("Operator UUID: %x", opUUID)
	op.VNetPools = pools

	if err := op.Start(); err != nil {
		log.Fatalf("Operator start: %v", err)
	}
	if opExternalAddr != "" {
		log.Infof("Operator started: client=%s (%s, %s), operator=%s (external %s)",
			a.ListenAddr, a.Transport, defaultAuth.Type(), opListenAddr, opExternalAddr)
	} else {
		log.Infof("Operator started: client=%s (%s, %s), operator=%s",
			a.ListenAddr, a.Transport, defaultAuth.Type(), opListenAddr)
	}
	waitForSignal()
	op.Close()
}

// --------------- Client ---------------

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	resolve := common.RegisterClientFlags(fs)
	fs.Parse(args)
	a := resolve()

	clientAuth, err := auth.ParseClientAuth(a.AuthStr, []byte("default-fingerprint"))
	if err != nil {
		log.Fatalf("Auth: %v", err)
	}

	var sessionID [16]byte
	dialer, err := createDialer(a.Transport, sessionID, a.VNetID, clientAuth)
	if err != nil {
		log.Fatalf("Dialer: %v", err)
	}

	c := client.New(&client.Config{
		Endpoint:  a.Endpoint,
		SessionID: sessionID,
		VNetID:    a.VNetID,
		TUNName:   a.TUNName,
		Dialer:    dialer,
	})

	if err := c.Start(); err != nil {
		log.Fatalf("Client start: %v", err)
	}
	log.Infof("Client connected to %s (%s, %s)", a.Endpoint, a.Transport, clientAuth.Type())
	waitForSignal()
	c.Close()
}

// --------------- Transport factories ---------------

func createListener(transportType, addr string, resolver auth.AuthResolver, configFn protocol.ConfigFunc) (transport.Listener, error) {
	switch transportType {
	case "tcp":
		return tcp.NewListener(addr, resolver, configFn)
	case "udp":
		return udp.NewListener(addr, resolver, configFn)
	case "quic":
		tlsConf, err := quic.GenerateServerTLS()
		if err != nil {
			return nil, err
		}
		return quic.NewListener(addr, resolver, configFn, tlsConf)
	default:
		return nil, fmt.Errorf("unknown transport: %s", transportType)
	}
}

func createDialer(transportType string, sessionID [16]byte, vnetID [16]byte, clientAuth auth.ClientAuthenticator) (transport.Dialer, error) {
	switch transportType {
	case "tcp":
		return tcp.NewDialer(sessionID, vnetID, clientAuth), nil
	case "udp":
		return udp.NewDialer(sessionID, vnetID, clientAuth), nil
	case "quic":
		return quic.NewDialer(sessionID, vnetID, clientAuth, quic.InsecureClientTLS()), nil
	default:
		return nil, fmt.Errorf("unknown transport: %s", transportType)
	}
}

func waitForSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	<-sigs
	log.Info("Shutting down...")
}
