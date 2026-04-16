package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/jabberwocky238/gasoline/client"
	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/operator"
	"github.com/jabberwocky238/gasoline/operator/hotreload/fswatch"
	hotreloadk8s "github.com/jabberwocky238/gasoline/operator/hotreload/k8s"
	"github.com/jabberwocky238/gasoline/protocol/auth"
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if cfg.WatchDir != "" {
		if err := op.RegisterReloader("fs", func(pools *operator.VNetPoolMap, resolver *auth.MapResolver, logger *log.Logger) (operator.HotReloader, error) {
			return fswatch.NewWatcher(ctx, cfg.WatchDir, pools, resolver, logger)
		}); err != nil {
			log.Fatalf("fswatch reloader: %v", err)
		}
	}
	if cfg.EnableK8s {
		if cfg.K8sNamespace == "" {
			log.Fatalf("k8s reloader: $POD_NAMESPACE not set")
		}
		if err := op.RegisterReloader("k8s", func(pools *operator.VNetPoolMap, resolver *auth.MapResolver, logger *log.Logger) (operator.HotReloader, error) {
			return hotreloadk8s.NewWatcher(ctx, hotreloadk8s.Config{
				Namespace: cfg.K8sNamespace,
				Pools:     pools,
				Resolver:  resolver,
				Logger:    logger,
			})
		}); err != nil {
			log.Fatalf("k8s reloader: %v", err)
		}
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

	cfg := resolve()
	if cfg.Logger == nil {
		cfg.Logger = log.StandardLogger()
	}
	c, err := client.New(cfg)
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
