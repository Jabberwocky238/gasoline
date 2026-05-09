package auth

import "github.com/jabberwocky238/gasoline/protocol"

// NoAuthClient sends device fingerprint during handshake.
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

func (a *NoAuthServer) Type() Type                         { return TypeNoAuth }
func (a *NoAuthServer) GenerateChallenge() ([]byte, error) { return nil, nil }

// VerifyResponse always succeeds for NoAuth.
func (a *NoAuthServer) VerifyResponse(_ protocol.CID_Ty, _, _ []byte) error {
	return nil
}
