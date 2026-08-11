package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/jabberwocky238/gasoline/cmd/client/device"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/noise"
	log "github.com/sirupsen/logrus"
)

func main() {
	// `client genkey` prints a fresh key pair and exits — the public key is
	// what an operator admin registers via --network / gasoctl key grant.
	if len(os.Args) > 1 && os.Args[1] == "genkey" {
		genkey()
		return
	}

	params := make(map[string][]string)
	collect := func(name, usage string) {
		flag.Func(name, usage, func(v string) error {
			params[name] = append(params[name], v)
			return nil
		})
	}
	collect(ParamEndpoint, "server address (required)")
	collect(ParamTransport, "transport: udp, quic (default quic)")
	collect(ParamVNI, "VNI (decimal, e.g. 200) (required)")
	collect(ParamKey, "client static private key (base64); generated if empty")
	collect(ParamServerPub, "operator static public key (base64) (required)")
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

// genkey prints a fresh Noise key pair plus the derived CID.
func genkey() {
	priv, pub, err := noise.GenerateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "genkey: %v\n", err)
		os.Exit(1)
	}
	cid := protocol.DeriveCID(pub)
	fmt.Printf("private: %s\n", base64.StdEncoding.EncodeToString(priv[:]))
	fmt.Printf("public:  %s\n", base64.StdEncoding.EncodeToString(pub[:]))
	fmt.Printf("cid:     %s\n", cid)
}
