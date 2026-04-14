package auth

import (
	"fmt"
	"sync"

	"github.com/jabberwocky238/gasoline/common"
)

// AuthResolver resolves a ServerAuthenticator for a given VNI.
// Used by the handshake to pick the correct per-VNet auth strategy.
type AuthResolver interface {
	Resolve(vni common.VNI) (ServerAuthenticator, error)
}

// MapResolver is a simple map-based AuthResolver with an optional default.
type MapResolver struct {
	mu          sync.RWMutex
	auths       map[common.VNI]ServerAuthenticator
	defaultAuth ServerAuthenticator // used when vni not found in map (nil = no fallback)
}

func NewMapResolver(defaultAuth ServerAuthenticator) *MapResolver {
	return &MapResolver{
		auths:       make(map[common.VNI]ServerAuthenticator),
		defaultAuth: defaultAuth,
	}
}

func (r *MapResolver) Set(vni common.VNI, auth ServerAuthenticator) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.auths[vni] = auth
}

func (r *MapResolver) Remove(vni common.VNI) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.auths, vni)
}

func (r *MapResolver) Resolve(vni common.VNI) (ServerAuthenticator, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if a, ok := r.auths[vni]; ok {
		return a, nil
	}
	if r.defaultAuth != nil {
		return r.defaultAuth, nil
	}
	return nil, fmt.Errorf("no auth configured for vni %s", vni)
}
