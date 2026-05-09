package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jabberwocky238/gasoline/device/cordinator"
	log "github.com/sirupsen/logrus"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP listen address (REST + websocket)")
	flag.Parse()
	if rest := flag.Args(); len(rest) > 0 {
		fmt.Fprintf(os.Stderr, "cordinator: unexpected args: %v\n", rest)
		os.Exit(2)
	}

	c := cordinator.New(*addr)
	if err := c.Start(); err != nil {
		log.Fatalf("cordinator start: %v", err)
	}

	log.Infof("cordinator started on %s; ctrl-c to quit", *addr)
	waitForSignal()
	_ = c.Close()
}

func waitForSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	<-sigs
	log.Info("Shutting down...")
}
