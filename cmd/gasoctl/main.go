package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/jabberwocky238/gasoline/protocol/control"
)

const defaultSocket = "/var/run/gasoline/operator.sock"

func main() {
	fs := flag.NewFlagSet("gasoctl", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	socket := fs.String("sock", envOr("GASOCTL_SOCK", defaultSocket), "operator IPC socket path")
	fs.Usage = usage(fs)

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	args := fs.Args()
	if len(args) == 0 {
		fs.Usage()
		os.Exit(2)
	}

	op, err := buildOp(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gasoctl: %v\n", err)
		os.Exit(2)
	}

	client := NewClient(*socket)
	reply, err := client.Send(op)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gasoctl: %v\n", err)
		os.Exit(1)
	}

	r, ok := reply.(*control.Reply)
	if !ok {
		fmt.Fprintf(os.Stderr, "gasoctl: unexpected reply type %T\n", reply)
		os.Exit(1)
	}
	if r.OK {
		if r.Payload != "" {
			fmt.Println("OK", r.Payload)
		} else {
			fmt.Println("OK")
		}
		return
	}
	fmt.Fprintln(os.Stderr, "ERR", r.Payload)
	os.Exit(1)
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}
