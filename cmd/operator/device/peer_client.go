package operator

import (
	"sync/atomic"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/transport"
)

// PeerClient represents a client connected to this operator.
type PeerClient struct {
	sc   *protocol.SessionContext
	Conn transport.Conn

	closed atomic.Bool
}

func newPeerClient(conn transport.Conn, h *protocol.SessionContext) *PeerClient {
	return &PeerClient{
		sc:   h,
		Conn: conn,
	}
}
