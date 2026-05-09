package auth

import (
	"fmt"

	"github.com/jabberwocky238/gasoline/protocol"
)

// Type identifies the authentication method on the wire.
type Type byte

const (
	TypeNoAuth   Type = 0x00
	TypeHMAC     Type = 0x01
	TypeUserPass Type = 0x02
)

func (t Type) String() string {
	switch t {
	case TypeNoAuth:
		return "NoAuth"
	case TypeHMAC:
		return "HMAC"
	case TypeUserPass:
		return "UserPass"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

// ClientAuthenticator is the client-side auth strategy.
type ClientAuthenticator interface {
	Type() Type
	// Respond processes the server challenge and returns the auth payload.
	Respond(challenge []byte) ([]byte, error)
}

// ServerAuthenticator is the server-side auth strategy.
type ServerAuthenticator interface {
	Type() Type
	// GenerateChallenge creates a nonce/salt for the client.
	GenerateChallenge() ([]byte, error)
	// VerifyResponse checks the client's auth response.
	// cid is the client identifier from ClientHello, used by auth strategies
	// that bind the response to the client identity (e.g. HMAC).
	VerifyResponse(cid protocol.CID_Ty, challenge, response []byte) error
}

// AuthResolver resolves a ServerAuthenticator for a given VNI.
// Used by the handshake to pick the correct per-VNet auth strategy.
type AuthResolver interface {
	Resolve(vni protocol.VNI_Ty) (ServerAuthenticator, error)
}
