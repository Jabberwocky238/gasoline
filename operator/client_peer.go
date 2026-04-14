package operator

import (
	"net/netip"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/transport"
)

// ClientPeer represents a client connected to the cluster.
type ClientPeer struct {
	Conn       transport.Conn
	SessionID  [common.SessionIDLen]byte    // unique ID for this session
	VNetID     [common.VNetIDLen]byte       // virtual network this client belongs to
	OperatorID [common.OperatorUUIDLen]byte // UUID of the operator this client is on
	IP         netip.Prefix                 // assigned IP
	AllowedIPs []netip.Prefix               // allowed IP ranges for this client
}

// ContainsIP reports whether addr falls within this client's AllowedIPs.
func (cp *ClientPeer) ContainsIP(addr netip.Addr) bool {
	for _, prefix := range cp.AllowedIPs {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
