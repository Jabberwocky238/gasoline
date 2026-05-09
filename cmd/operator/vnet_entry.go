package operator

import (
	"context"
	"errors"
	"net/netip"
	"sync"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
)

type vniEntry struct {
	mu            sync.RWMutex
	anthenticator auth.ServerAuthenticator
	clients       map[protocol.VNI_Ty]*PeerClient
	vnetPool      *VNetIpPool
}

// Clients returns a snapshot copy of the per-VNI client map.
func (v *vniEntry) Clients() []*PeerClient {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]*PeerClient, 0, len(v.clients))
	for _, cp := range v.clients {
		out = append(out, cp)
	}
	return out
}
