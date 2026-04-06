package common

type Transport byte

const (
	TCP Transport = iota
	UDP
	QUIC
)

func (t Transport) String() string {
	switch t {
	case TCP:
		return "TCP"
	case UDP:
		return "UDP"
	case QUIC:
		return "QUIC"
	default:
		return "Unknown"
	}
}

func (t Transport) Network() string {
	switch t {
	case TCP:
		return "tcp"
	case UDP, QUIC:
		return "udp"
	default:
		return ""
	}
}
