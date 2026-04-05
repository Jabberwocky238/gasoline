package protocol

const (
	HandshakeVersion = 0x01
)

type Handshake struct {
	Version   byte
	Transport byte
}
