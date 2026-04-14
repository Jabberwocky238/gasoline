package transport

import (
	"time"

	"github.com/jabberwocky238/gasoline/protocol"
)

// Conn is a packet-oriented, AEAD-encrypted connection.
// Each ReadPacket returns exactly one decrypted IP packet.
// Each WritePacket sends exactly one encrypted IP packet.
// Framing is handled internally per transport:
//   - UDP: one datagram = one packet (no framing needed)
//   - TCP/QUIC: length-prefix framing over the byte stream
//
// LastActive returns the timestamp of the most recent successful ReadPacket or WritePacket.
// Callers (operator, client) use this to determine session liveness without
// application-level keepalive messages.
type Conn interface {
	ReadPacket(buf []byte) (int, error)
	WritePacket(data []byte) error
	Close() error
	RemoteAddr() string
	LastActive() time.Time
}

// Dialer creates outbound connections with handshake + AEAD.
type Dialer interface {
	Dial(endpoint string) (Conn, *protocol.HandshakeResult, error)
}

// Listener accepts inbound connections with handshake + AEAD.
type Listener interface {
	Accept() (Conn, *protocol.HandshakeResult, error)
	Close() error
	Addr() string
}
