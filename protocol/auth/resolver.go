package auth

import (
	"fmt"
	"sync"

	"github.com/jabberwocky238/gasoline/common"
)

// AuthResolver resolves a ServerAuthenticator for a given VNetID.
// Used by the handshake to pick the correct per-VNet auth strategy.
type AuthResolver interface {
	Resolve(vnetID [common.VNetIDLen]byte) (ServerAuthenticator, error)
}

// MapResolver is a simple map-based AuthResolver with an optional default.
type MapResolver struct {
	mu          sync.RWMutex
	auths       map[[common.VNetIDLen]byte]ServerAuthenticator
	defaultAuth ServerAuthenticator // used when vnetID not found in map (nil = no fallback)
}

func NewMapResolver(defaultAuth ServerAuthenticator) *MapResolver {
	return &MapResolver{
		auths:       make(map[[common.VNetIDLen]byte]ServerAuthenticator),
		defaultAuth: defaultAuth,
	}
}

func (r *MapResolver) Set(vnetID [common.VNetIDLen]byte, auth ServerAuthenticator) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.auths[vnetID] = auth
}

func (r *MapResolver) Remove(vnetID [common.VNetIDLen]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.auths, vnetID)
}

func (r *MapResolver) Resolve(vnetID [common.VNetIDLen]byte) (ServerAuthenticator, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if a, ok := r.auths[vnetID]; ok {
		return a, nil
	}
	if r.defaultAuth != nil {
		return r.defaultAuth, nil
	}
	return nil, fmt.Errorf("no auth configured for vnet %x", vnetID)
}
