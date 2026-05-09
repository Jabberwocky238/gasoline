package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/jabberwocky238/gasoline/device/gasoctl"
)

const defaultSocket = "/var/run/gasoline/operator.sock"

func main() {
	fs := flag.NewFlagSet("gasoctl", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	socket := fs.String("sock", envOr("GASOCTL_SOCK", defaultSocket), "operator IPC socket path")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: gasoctl [-sock <path>] <command> [args...]

Commands:
  route set <cid-hex> <prefix>
  route get <cid-hex>
  route del <cid-hex>
  cordinator connect    <endpoint>
  cordinator disconnect <endpoint>

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	args := fs.Args()
	if len(args) == 0 {
		fs.Usage()
		os.Exit(2)
	}

	client := gasoctl.NewClient(*socket)
	reply, err := client.Send(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gasoctl: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(reply)
	if strings.HasPrefix(reply, "ERR ") {
		os.Exit(1)
	}
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}
