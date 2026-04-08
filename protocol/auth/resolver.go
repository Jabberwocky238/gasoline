package auth

import "fmt"

// AuthResolver resolves a ServerAuthenticator for a given VNetID.
// Used by the handshake to pick the correct per-VNet auth strategy.
type AuthResolver interface {
	Resolve(vnetID [16]byte) (ServerAuthenticator, error)
}

// MapResolver is a simple map-based AuthResolver with an optional default.
type MapResolver struct {
	auths      map[[16]byte]ServerAuthenticator
	defaultAuth ServerAuthenticator // used when vnetID not found in map (nil = no fallback)
}

func NewMapResolver(defaultAuth ServerAuthenticator) *MapResolver {
	return &MapResolver{
		auths:      make(map[[16]byte]ServerAuthenticator),
		defaultAuth: defaultAuth,
	}
}

func (r *MapResolver) Set(vnetID [16]byte, auth ServerAuthenticator) {
	r.auths[vnetID] = auth
}

func (r *MapResolver) Resolve(vnetID [16]byte) (ServerAuthenticator, error) {
	if a, ok := r.auths[vnetID]; ok {
		return a, nil
	}
	if r.defaultAuth != nil {
		return r.defaultAuth, nil
	}
	return nil, fmt.Errorf("no auth configured for vnet %x", vnetID)
}
