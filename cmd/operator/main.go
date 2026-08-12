package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/jabberwocky238/gasoline/cmd/operator/device"
	"github.com/jabberwocky238/gasoline/cmd/operator/device/consensus"
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
	collect(ParamKey, "operator static private key, base64 (generated if unset)")
	collect(ParamListen, "client listener '<schema>://<addr>' (repeatable; default quic://:8443)")
	collect(ParamRoot, "config dir: one YAML per vnet, fsnotify-watched (PRD §4.4)")
	collect(ParamHopEndpoint, "advertisable hop target 'uuid@host:lo-hi[,lo-hi]' (repeatable)")
	collect(ParamRaftBind, "this node's Raft QUIC listen address (enables consensus)")
	collect(ParamRaftPeers, "Raft cluster members 'id@host:port;id2@host:port2'")
	collect(ParamRaftBootstrap, "'true' on exactly one node to seed a fresh cluster")
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

	// Consensus: build and attach a Raft node when --raft-bind was given, so
	// IP/SessionID allocation commits through Raft. Without it the operator
	// runs the pre-consensus preset allocator.
	var raftNode *consensus.Node
	if cfg.Raft != nil {
		peers := make([]consensus.Peer, len(cfg.Raft.Peers))
		for i, p := range cfg.Raft.Peers {
			peers[i] = consensus.Peer{ID: p.ID, Addr: p.Addr}
		}
		// LocalID must match a peer entry (so this node is in its own voter
		// set). Default it to the peer whose address equals --raft-bind.
		localID := cfg.Raft.LocalID
		if localID == "" {
			for _, p := range cfg.Raft.Peers {
				if p.Addr == cfg.Raft.BindAddr {
					localID = p.ID
					break
				}
			}
		}
		if localID == "" {
			log.Fatalf("consensus: cannot determine local Raft ID; add a --raft-peers entry whose address matches --raft-bind %q", cfg.Raft.BindAddr)
		}
		raftNode, err = consensus.NewNode(consensus.Config{
			LocalID:   localID,
			BindAddr:  cfg.Raft.BindAddr,
			Peers:     peers,
			Bootstrap: cfg.Raft.Bootstrap,
		})
		if err != nil {
			log.Fatalf("consensus init: %v", err)
		}
		op.AttachConsensus(raftNode)
		log.Infof("Consensus (Raft) enabled: id=%s bind=%s peers=%d bootstrap=%v",
			localID, cfg.Raft.BindAddr, len(peers), cfg.Raft.Bootstrap)
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

	// Clients encrypt their Noise_IK initiation to this key and must be
	// configured with it out of band (-server-pub), so it has to be
	// discoverable — especially when it was generated rather than
	// supplied via -key.
	staticPub := op.StaticPub()
	log.Infof("Operator %x started; ipc on %s", op.UUID(), ipc.Path())
	log.Infof("Operator static public key: %s", base64.StdEncoding.EncodeToString(staticPub[:]))
	waitForSignal()

	_ = ipc.Close()
	_ = op.Close()
	if raftNode != nil {
		_ = raftNode.Shutdown()
	}
}

func printConfig(cfg *operator.StaticOperatorConfig, ipcSocket string) {
	fmt.Printf("op-listen: %s\n", cfg.OpListenAddr)
	fmt.Printf("log-level: %s\n", cfg.LogLevel)
	fmt.Printf("ipc:       %s\n", ipcSocket)
	fmt.Println("listeners:")
	for _, l := range cfg.ClientListeners {
		fmt.Printf("  - %s://%s\n", l.Transport, l.Addr)
	}
	if cfg.RootDir != "" {
		fmt.Printf("root:      %s (vnets loaded + fsnotify-watched)\n", cfg.RootDir)
	} else {
		fmt.Println("root:      (none)")
	}
	if cfg.Raft != nil {
		fmt.Printf("raft:      bind=%s peers=%d bootstrap=%v\n",
			cfg.Raft.BindAddr, len(cfg.Raft.Peers), cfg.Raft.Bootstrap)
	} else {
		fmt.Println("raft:      disabled")
	}
}

func waitForSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	<-sigs
	log.Info("Shutting down...")
}
