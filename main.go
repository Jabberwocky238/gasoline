package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/jabberwocky238/gasoline/client"
	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/operator"
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

func runOperator(args []string) {
	fs := flag.NewFlagSet("operator", flag.ExitOnError)
	resolve := common.RegisterOperatorFlags(fs)
	fs.Parse(args)
	cfg := resolve()

	op, err := operator.New(cfg)
	if err != nil {
		log.Fatalf("Operator init: %v", err)
	}

	if err := op.Start(); err != nil {
		log.Fatalf("Operator start: %v", err)
	}

	log.Infof("Operator %x started: client=%s (%s), operator=%s",
		op.UUID(), cfg.ListenAddr, cfg.Transport, cfg.OpListenAddr)

	waitForSignal()
	op.Close()
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	resolve := common.RegisterClientFlags(fs)
	fs.Parse(args)
	cfg := resolve()

	clientAuth, err := auth.ParseClientAuth(cfg.AuthStr, []byte("default-fingerprint"))
	if err != nil {
		log.Fatalf("Auth: %v", err)
	}

	var sessionID [16]byte
	dialer, err := createDialer(cfg.Transport, sessionID, cfg.VNetID, clientAuth)
	if err != nil {
		log.Fatalf("Dialer: %v", err)
	}

	c := client.New(&client.Config{
		Endpoint:  cfg.Endpoint,
		SessionID: sessionID,
		VNetID:    cfg.VNetID,
		TUNName:   cfg.TUNName,
		Dialer:    dialer,
	})

	if err := c.Start(); err != nil {
		log.Fatalf("Client start: %v", err)
	}
	log.Infof("Client connected to %s (%s, %s)", cfg.Endpoint, cfg.Transport, clientAuth.Type())
	waitForSignal()
	c.Close()
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
