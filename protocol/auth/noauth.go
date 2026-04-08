package auth

// NoAuthClient sends device fingerprint during handshake.
// VNetID is now sent in the ClientHello, not in the auth payload.
type NoAuthClient struct {
	Fingerprint []byte
}

func (a *NoAuthClient) Type() Type { return TypeNoAuth }

// Respond sends the fingerprint as the auth payload.
func (a *NoAuthClient) Respond(_ []byte) ([]byte, error) {
	return a.Fingerprint, nil
}

// NoAuthServer accepts any client without verification.
type NoAuthServer struct{}

func (a *NoAuthServer) Type() Type                        { return TypeNoAuth }
func (a *NoAuthServer) GenerateChallenge() ([]byte, error) { return nil, nil }

// VerifyResponse always succeeds for NoAuth.
func (a *NoAuthServer) VerifyResponse(_ [16]byte, _, _ []byte) error {
	return nil
}
