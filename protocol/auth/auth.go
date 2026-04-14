package auth

import (
	"fmt"

	"github.com/jabberwocky238/gasoline/common"
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
	VerifyResponse(vmac common.VMAC, challenge, response []byte) error
}
