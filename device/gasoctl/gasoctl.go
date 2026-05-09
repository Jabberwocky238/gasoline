// Package gasoctl is the operator's control-plane CLI sender.
//
// It only knows how to format a command line, dial a Unix socket,
// write the line, and read back one reply line. Parsing and dispatch
// of these commands lives on the receiving side
// (device/operator).
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
	"time"

	"github.com/jabberwocky238/gasoline/protocol"
)

// Client is a one-shot gasoctl client bound to a single Unix socket
// path. Each Send dials, writes one line, reads one line, and closes.
type Client struct {
	Socket  string
	Timeout time.Duration // 0 = no timeout
}

// NewClient returns a Client targeting socket. socket must be the path
// to the operator's IPC unix socket.
func NewClient(socket string) *Client {
	return &Client{Socket: socket}
}

// Send dials the socket, writes a single command line built from args,
// and returns the reply line (no trailing newline). args is the same
// form the user typed: e.g. {"route","set",cid,pfx}.
func (c *Client) Send(args []string) (string, error) {
	if c.Socket == "" {
		return "", fmt.Errorf("gasoctl: empty socket path")
	}
	if len(args) == 0 {
		return "", fmt.Errorf("gasoctl: empty command")
	}

	var (
		conn net.Conn
		err  error
	)
	if c.Timeout > 0 {
		conn, err = net.DialTimeout("unix", c.Socket, c.Timeout)
	} else {
		conn, err = net.Dial("unix", c.Socket)
	}
	if err != nil {
		return "", fmt.Errorf("gasoctl: dial %s: %w", c.Socket, err)
	}
	defer conn.Close()

	if c.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(c.Timeout))
	}

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
