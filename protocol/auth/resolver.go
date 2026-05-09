package auth

import (
	"fmt"
	"sync"

	"github.com/jabberwocky238/gasoline/protocol"
)

// AuthResolver resolves a ServerAuthenticator for a given VNI.
// Used by the handshake to pick the correct per-VNet auth strategy.
type AuthResolver interface {
	Resolve(vni protocol.VNI_Ty) (ServerAuthenticator, error)
}

// MapResolver is a simple map-based AuthResolver with an optional default.
type MapResolver struct {
	mu    sync.RWMutex
	auths map[protocol.VNI_Ty]ServerAuthenticator
}

func NewMapResolver() *MapResolver {
	return &MapResolver{
		auths: make(map[protocol.VNI_Ty]ServerAuthenticator),
	}
}

func (r *MapResolver) Set(vni protocol.VNI_Ty, auth ServerAuthenticator) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.auths[vni] = auth
}

func (r *MapResolver) Remove(vni protocol.VNI_Ty) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.auths, vni)
}

func (r *MapResolver) Resolve(vni protocol.VNI_Ty) (ServerAuthenticator, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if a, ok := r.auths[vni]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("no auth configured for vni %d", vni)
}
