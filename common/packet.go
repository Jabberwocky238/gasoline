package common

import "net"

type IpVersionType byte

const (
	IPv4 IpVersionType = 0x04
	IPv6 IpVersionType = 0x06
)

const (
	SessionIDLen    = 16
	OperatorUUIDLen = 16
	VNetIDLen       = 16
)

const (
	DefaultUDPBufferSize = 2 << 13 // 16KB
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

type Metadata struct {
	IpVersion IpVersionType `json:"ipVersion"`
	SrcIP     net.IP        `json:"sourceIP"`
	DstIP     net.IP        `json:"destinationIP"`
	SrcPort   uint16        `json:"sourcePort"`
	DstPort   uint16        `json:"destinationPort"`
}

type Packet interface {
	Data() []byte
	Metadata() *Metadata
}
