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

const defaultIPCSocket = "/var/run/gasoline/operator.sock"

func main() {
	params := make(map[string][]string)
	collect := func(name, usage string) {
		flag.Func(name, usage, func(v string) error {
			params[name] = append(params[name], v)
			return nil
		})
	}
	collect(ParamOpListen, "VXLAN UDP data-plane bind address (default 0.0.0.0:6677)")
	collect(ParamLogLevel, "log level: trace, debug, info, warn, error (default info)")
	collect(ParamListen, "client listener '<schema>://<addr>' (repeatable; default quic://:8443)")
	collect(ParamNetwork, "vnet entry '<vni>:<cidr>:<authtype>[:<authdata>]' (repeatable; default 0:10.0.0.0/24:noauth)")
	collect(ParamPreset, "preset cid->prefix '<vni>:<cid-hex>:<prefix>' (repeatable)")
	ipcSocket := flag.String("ipc", defaultIPCSocket, "gasoctl IPC unix socket path")
	dryRun := flag.Bool("dry-run", false, "parse and validate config, print it, then exit")

	flag.Parse()
	if rest := flag.Args(); len(rest) > 0 {
		fmt.Fprintf(os.Stderr, "operator: unexpected args: %s\n", strings.Join(rest, " "))
		os.Exit(2)
	}

	cfg, err := RegisterOperatorCLIParam(params)
	if err != nil {
		fmt.Fprintf(os.Stderr, "operator: %v\n", err)
		os.Exit(2)
	}

	if *dryRun {
		printConfig(cfg, *ipcSocket)
		return
	}

	op, err := operator.New(cfg)
	if err != nil {
		log.Fatalf("operator init: %v", err)
	}
	if err := op.Start(); err != nil {
		log.Fatalf("operator start: %v", err)
	}

	ipc, err := operator.NewIPC(op.NewControllerBase(), *ipcSocket)
	if err != nil {
		log.Fatalf("ipc init: %v", err)
	}
	if err := ipc.Start(); err != nil {
		log.Fatalf("ipc start: %v", err)
	}

	log.Infof("Operator %x started; ipc on %s", op.UUID(), ipc.Path())
	waitForSignal()

	_ = ipc.Close()
	_ = op.Close()
}

func printConfig(cfg *operator.StaticOperatorConfig, ipcSocket string) {
	fmt.Printf("op-listen: %s\n", cfg.OpListenAddr)
	fmt.Printf("log-level: %s\n", cfg.LogLevel)
	fmt.Printf("ipc:       %s\n", ipcSocket)
	fmt.Println("listeners:")
	for _, l := range cfg.ClientListeners {
		fmt.Printf("  - %s://%s\n", l.Transport, l.Addr)
	}
	fmt.Println("network:")
	for vni, n := range cfg.Network {
		fmt.Printf("  - vni=%d cidr=%s auth=%T preset=%d\n", vni, n.CIDR, n.Auth, len(n.PresetCIDmap))
		for cid, pfx := range n.PresetCIDmap {
			fmt.Printf("      %x -> %s\n", cid, pfx)
		}
	}
}

func waitForSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	<-sigs
	log.Info("Shutting down...")
}
