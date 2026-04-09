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

	op, err := operator.New(resolve())
	if err != nil {
		log.Fatalf("Operator init: %v", err)
	}
	if err := op.Start(); err != nil {
		log.Fatalf("Operator start: %v", err)
	}

	log.Infof("Operator %x started", op.UUID())
	waitForSignal()
	op.Close()
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	resolve := common.RegisterClientFlags(fs)
	fs.Parse(args)

	c, err := client.New(resolve())
	if err != nil {
		log.Fatalf("Client init: %v", err)
	}
	if err := c.Start(); err != nil {
		log.Fatalf("Client start: %v", err)
	}

	log.Infof("Client started")
	waitForSignal()
	c.Close()
}

func waitForSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	<-sigs
	log.Info("Shutting down...")
}
