// Package gasoctl is the operator's control-plane CLI sender.
//
// Wire format is one JSON envelope per line over the operator's
// Unix socket. The structs come from protocol/control:
//
//	request:  Envelope{Kind, Body=concrete Op JSON}
//	reply:    Envelope{Kind=KindReply, Body=Reply JSON}
//
// This is the same wire used between operator and cordinator (see
// device/cordinator); only the transport differs.
package main

import (
	"bufio"
	"fmt"
	"net"
	"time"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/control"
)

// Client is a one-shot gasoctl client bound to a single Unix socket
// path. Each Send dials, writes one JSON line, reads one JSON line,
// and closes.
type Client struct {
	Socket  string
	Timeout time.Duration // 0 = no timeout
}

// NewClient returns a Client targeting socket. socket must be the
// path to the operator's IPC unix socket.
func NewClient(socket string) *Client {
	return &Client{Socket: socket}
}

// Send dials the socket, writes one JSON envelope for op, reads one
// JSON envelope back, and returns the decoded Op.
func (c *Client) Send(op control.Op) (control.Op, error) {
	if c.Socket == "" {
		return nil, fmt.Errorf("gasoctl: empty socket path")
	}
	if op == nil {
		return nil, fmt.Errorf("gasoctl: nil op")
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
		return nil, fmt.Errorf("gasoctl: dial %s: %w", c.Socket, err)
	}
	defer conn.Close()

	if c.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(c.Timeout))
	}

	body, err := control.MarshalJSON(op)
	if err != nil {
		return nil, fmt.Errorf("gasoctl: marshal: %w", err)
	}
	if _, err := conn.Write(append(body, '\n')); err != nil {
		return nil, fmt.Errorf("gasoctl: write: %w", err)
	}

	r := bufio.NewReader(conn)
	line, err := r.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("gasoctl: read reply: %w", err)
	}
	reply, err := control.UnmarshalJSON(line)
	if err != nil {
		return nil, fmt.Errorf("gasoctl: decode reply: %w", err)
	}
	return reply, nil
}

// FormatCID renders a CID as the decimal uint64 string the CLI accepts.
func FormatCID(cid protocol.CID_Ty) string { return protocol.FormatCID(cid) }
