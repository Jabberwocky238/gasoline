package operator

import (
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/transport"
)

// PeerClient represents a client connected to this operator.
type PeerClient struct {
	id      string
	Conn    transport.Conn
	Session protocol.SessionContext
}
