package operator

import (
	"net/netip"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/transport"
)

// PeerClient represents a client connected to this operator.
type PeerClient struct {
	id         string
	Conn       transport.Conn
	SessionID  [16]byte       // assigned at handshake; index for stats / cross-operator session map
	VNI        common.VNI     // virtual network (24-bit VXLAN VNI)
	IP         netip.Prefix   // assigned IP
	AllowedIPs []netip.Prefix // allowed IP ranges for this client
}

// ContainsIP reports whether addr falls within this client's AllowedIPs.
func (cp *PeerClient) ContainsIP(addr netip.Addr) bool {
	for _, prefix := range cp.AllowedIPs {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// ID is the FDB-stable identifier for this client's L2 attachment.
func (p *PeerClient) ID() string { return p.id }
