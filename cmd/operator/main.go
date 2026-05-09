package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/jabberwocky238/gasoline/device/operator"
	log "github.com/sirupsen/logrus"
)

func main() {
	params, err := parseCLI(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "operator: %v\n", err)
		os.Exit(2)
	}

	cfg, err := RegisterOperatorCLIParam(params)
	if err != nil {
		fmt.Fprintf(os.Stderr, "operator: %v\n", err)
		os.Exit(2)
	}

	op, err := operator.New(cfg)
	if err != nil {
		log.Fatalf("operator init: %v", err)
	}
	if err := op.Start(); err != nil {
		log.Fatalf("operator start: %v", err)
	}

	log.Infof("Operator %x started", op.UUID())
	waitForSignal()
	op.Close()
}

// parseCLI uses the standard flag package to turn os.Args-style tokens into
// a map[string][]string keyed by option name. Repeatable options accumulate;
// single-valued options end up as a 1-element slice.
func parseCLI(args []string) (map[string][]string, error) {
	fs := flag.NewFlagSet("operator", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	out := make(map[string][]string)
	collect := func(name, usage string) {
		fs.Func(name, usage, func(v string) error {
			out[name] = append(out[name], v)
			return nil
		})
	}

	collect(ParamOpListen, "VXLAN UDP data-plane bind address (default 0.0.0.0:6677)")
	collect(ParamLogLevel, "log level: trace, debug, info, warn, error (default info)")
	collect(ParamListen, "client listener '<schema>://<addr>' (repeatable; default quic://:8443)")
	collect(ParamNetwork, "vnet entry '<vni>:<cidr>' (repeatable; default 0:10.0.0.0/24)")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if rest := fs.Args(); len(rest) > 0 {
		return nil, fmt.Errorf("unexpected positional arguments: %s", strings.Join(rest, " "))
	}
	return out, nil
}

func waitForSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	<-sigs
	log.Info("Shutting down...")
}
