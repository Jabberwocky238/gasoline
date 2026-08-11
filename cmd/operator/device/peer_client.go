package operator

import (
	"sync/atomic"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/noise"
	"github.com/jabberwocky238/gasoline/transport"
)

// PeerClient represents a client connected to this operator.
type PeerClient struct {
	sc   *protocol.SessionContext
	Conn transport.Conn

	// session is the data-plane session for THIS conn (the client handshook
	// here). It decrypts frames read from Conn and encrypts frames written to
	// it. A client that hopped in from elsewhere is served via FSM keys, not
	// this field — see the shared-socket demux (PRD §6.4).
	session *noise.Session

	closed atomic.Bool
}

func newPeerClient(conn transport.Conn, h *protocol.SessionContext, session *noise.Session) *PeerClient {
	return &PeerClient{
		sc:      h,
		Conn:    conn,
		session: session,
	}
}
