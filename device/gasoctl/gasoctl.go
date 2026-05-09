// Package gasoctl is the operator's control-plane CLI sender.
//
// It only knows how to format a command line, dial a Unix socket,
// write the line, and read back one reply line. Parsing and dispatch
// of these commands lives on the receiving side
// (device/operator/controller).
//
// Wire format is one line per command, space-separated:
//
//	route set <cid-hex> <prefix>
//	route get <cid-hex>
//	route del <cid-hex>
//	cordinator connect    <endpoint>
//	cordinator disconnect <endpoint>
//
// Replies are also one line:
//
//	OK [<payload>]
//	ERR <message>
package gasoctl

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/jabberwocky238/gasoline/protocol"
)

// Send dials socket, writes a single command line built from args, and
// returns the reply line (with its trailing newline stripped). args is
// expected in the same form the user typed: e.g. {"route","set",cid,pfx}.
func Send(socket string, args []string) (string, error) {
	if socket == "" {
		return "", fmt.Errorf("gasoctl: empty socket path")
	}
	if len(args) == 0 {
		return "", fmt.Errorf("gasoctl: empty command")
	}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return "", fmt.Errorf("gasoctl: dial %s: %w", socket, err)
	}
	defer conn.Close()

	line := strings.Join(args, " ") + "\n"
	if _, err := conn.Write([]byte(line)); err != nil {
		return "", fmt.Errorf("gasoctl: write: %w", err)
	}
	r := bufio.NewReader(conn)
	reply, err := r.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("gasoctl: read reply: %w", err)
	}
	return strings.TrimRight(reply, "\r\n"), nil
}

// FormatCID renders a CID as the 16-char hex string the CLI accepts.
func FormatCID(cid protocol.CID_Ty) string {
	return hex.EncodeToString(cid[:])
}
