package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/control"
)

// parseSessionID decodes a 16-byte SessionID from a 32-char hex string.
func parseSessionID(s string) (protocol.SessionID_Ty, error) {
	var sid protocol.SessionID_Ty
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return sid, fmt.Errorf("session-id %q: invalid hex: %v", s, err)
	}
	if len(b) != len(sid) {
		return sid, fmt.Errorf("session-id %q: want %d bytes, got %d", s, len(sid), len(b))
	}
	copy(sid[:], b)
	return sid, nil
}

// buildOp turns a gasoctl argv tail (e.g. {"route","set","0","123","10.0.0.5/32"})
// into a typed control.Op the client can ship over the wire.
func buildOp(args []string) (control.Op, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("missing command")
	}
	switch args[0] {
	case "route":
		return buildRouteOp(args[1:])
	default:
		return nil, fmt.Errorf("unknown command %q", args[0])
	}
}

func buildRouteOp(args []string) (control.Op, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("route: missing subcommand")
	}
	switch args[0] {
	case "set":
		if len(args) != 4 {
			return nil, fmt.Errorf("route set: usage 'route set <vni> <session-id-hex> <prefix>'")
		}
		vni, err := parseVNI(args[1])
		if err != nil {
			return nil, err
		}
		sid, err := parseSessionID(args[2])
		if err != nil {
			return nil, err
		}
		pfx, err := netip.ParsePrefix(args[3])
		if err != nil {
			return nil, fmt.Errorf("bad prefix %q: %v", args[3], err)
		}
		return &control.RouteUpsert{VNI: vni, SessionID: sid, Prefix: pfx}, nil

	case "get":
		if len(args) != 3 {
			return nil, fmt.Errorf("route get: usage 'route get <vni> <session-id-hex>'")
		}
		vni, err := parseVNI(args[1])
		if err != nil {
			return nil, err
		}
		sid, err := parseSessionID(args[2])
		if err != nil {
			return nil, err
		}
		return &control.RouteQuery{VNI: vni, SessionID: sid}, nil

	case "del":
		if len(args) != 3 {
			return nil, fmt.Errorf("route del: usage 'route del <vni> <session-id-hex>'")
		}
		vni, err := parseVNI(args[1])
		if err != nil {
			return nil, err
		}
		sid, err := parseSessionID(args[2])
		if err != nil {
			return nil, err
		}
		return &control.RouteRemove{VNI: vni, SessionID: sid}, nil

	default:
		return nil, fmt.Errorf("route: unknown op %q", args[0])
	}
}

func parseVNI(s string) (protocol.VNI_Ty, error) {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("bad vni %q: %v", s, err)
	}
	return protocol.VNI_Ty(v), nil
}

// usage prints the gasoctl help text on the FlagSet's output.
func usage(fs *flag.FlagSet) func() {
	return func() {
		fmt.Fprintf(os.Stderr, `Usage: gasoctl [-sock <path>] <command> [args...]

Commands:
  route set        <vni> <session-id-hex> <prefix>
  route get        <vni> <session-id-hex>
  route del        <vni> <session-id-hex>

cid: decimal uint64 (default) or "0x..." hex.

Flags:
`)
		fs.PrintDefaults()
	}
}
