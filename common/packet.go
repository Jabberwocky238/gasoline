package common

const (
	SessionIDLen    = 16
	OperatorUUIDLen = 16
	VNetIDLen       = 16
)

// Client↔Operator packet type prefix (first byte of plaintext, before AEAD encryption).
// Transport layer is unaware — this is added/stripped at the application layer.
const (
	PacketData      byte = 0x00 // [0x00][IP packet...]
	PacketKeepalive byte = 0x01 // [0x01] (no payload)
)

const (
	KeepaliveInterval = 5  // seconds
	KeepaliveTimeout  = 18 // seconds (3 missed intervals + margin)
)
