package protocol

const (
	HandshakeVersion = 0x01
)

type HandshakeType byte

const (
	NoAuth HandshakeType = iota
	UserPassAuth
	EabKeyHmac
)

type ServerConfigType byte

const (
	NoConfig ServerConfigType = iota
	WgConfig
)

type HandshakeClienthello struct {
	version  byte
	clientID [16]byte
}

type HandshakeServerhello struct {
	version   byte
	transport HandshakeType
	payload   [256]byte
}

type HandshakeClientRequest struct {
	payload [256]byte
}

type HandshakeServerResponse struct {
	config [256]byte
}
