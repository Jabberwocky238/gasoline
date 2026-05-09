package operator

import (
	"sync/atomic"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/handshake"
	"github.com/jabberwocky238/gasoline/transport"
)

// PeerClient represents a client connected to this operator.
type PeerClient struct {
	SessionIndex uint32
	CID          protocol.CID_Ty
	VNI          protocol.VNI_Ty
	Conn         transport.Conn

	closed atomic.Bool
}

func newPeerClient(conn transport.Conn, h *handshake.HandshakeResult) *PeerClient {
	return &PeerClient{
		SessionIndex: h.SessionIndex,
		CID:          h.CID,
		VNI:          h.VNI,
		Conn:         conn,
	}
}
