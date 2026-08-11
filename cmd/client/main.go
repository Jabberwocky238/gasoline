package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/jabberwocky238/gasoline/cmd/client/device"
	log "github.com/sirupsen/logrus"
)

func main() {
	params := make(map[string][]string)
	collect := func(name, usage string) {
		flag.Func(name, usage, func(v string) error {
			params[name] = append(params[name], v)
			return nil
		})
	}
	collect(ParamEndpoint, "server address (required)")
	collect(ParamTransport, "transport: udp, quic (default quic)")
	collect(ParamAuth, "auth config string (default noauth)")
	collect(ParamVNI, "VNI (decimal, e.g. 200) (required)")
	collect(ParamCID, "preassigned client ID (16 hex chars; auto-generated if empty)")
	collect(ParamTUN, "TUN device name (empty = raw mode, no TUN)")
	collect(ParamLogLevel, "log level: trace, debug, info, warn, error (default info)")

	flag.Parse()
	if rest := flag.Args(); len(rest) > 0 {
		fmt.Fprintf(os.Stderr, "client: unexpected args: %s\n", strings.Join(rest, " "))
		os.Exit(2)
	}

	cfg, err := RegisterClientCLIParam(params)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client: %v\n", err)
		os.Exit(2)
	}

	c, err := client.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client init: %v\n", err)
		os.Exit(1)
	}
	if err := c.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "client start: %v\n", err)
		os.Exit(1)
	}

	log.Info("client started; ctrl-c to quit")
	waitForSignal()
	_ = c.Close()
}

func waitForSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	<-sigs
	log.Info("Shutting down...")
}
