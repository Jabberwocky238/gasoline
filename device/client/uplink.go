package client

import (
	"sync/atomic"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/transport"
)

// uplink owns the rxLoop on a transport.Conn and hands every received
// frame to onFrame. Without a vtep / FDB we don't do L2 routing; the
// client just receives broadcast traffic from peers and the caller
// decides what to do with it.
type uplink struct {
	lctx    *common.LogContext
	conn    transport.Conn
	onFrame func([]byte)

	closed atomic.Bool
}

func newUplink(parent *common.LogContext, conn transport.Conn, onFrame func([]byte)) *uplink {
	if onFrame == nil {
		onFrame = func([]byte) {}
	}
	return &uplink{
		lctx:    parent.WithField("component", "uplink"),
		conn:    conn,
		onFrame: onFrame,
	}
}

// SendFrame writes one frame to the transport.
func (u *uplink) SendFrame(frame []byte) error {
	if u.closed.Load() {
		return nil
	}
	return u.conn.WritePacket(frame)
}

// Start spawns the rxLoop reading from the transport and dispatching.
func (u *uplink) Start() { go u.rxLoop() }

// Close stops the rxLoop. The transport.Conn is not closed here —
// ownership stays with the Client.
func (u *uplink) Close() error {
	if !u.closed.CompareAndSwap(false, true) {
		return nil
	}
	u.lctx.Cancel()
	return nil
}

func (u *uplink) rxLoop() {
	bufp := common.GetBuffer()
	defer common.PutBuffer(bufp)
	buf := *bufp
	for {
		select {
		case <-u.lctx.Done():
			return
		default:
		}
		n, err := u.conn.ReadPacket(buf)
		if err != nil {
			if u.closed.Load() {
				return
			}
			u.lctx.Log().Debugf("conn read: %v", err)
			return
		}
		if n == 0 {
			continue
		}
		// Drop the operator's keepalive reply (IP version 3); the client
		// doesn't echo back, otherwise we'd ping-pong forever.
		if buf[0]>>4 == 3 {
			continue
		}
		frame := make([]byte, n)
		copy(frame, buf[:n])
		u.onFrame(frame)
	}
}
