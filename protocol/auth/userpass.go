package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"github.com/jabberwocky238/gasoline/common"
)

const saltSize = 32

// UserPassClient authenticates with a user ID and password.
// Auth field format: userpass:<userid>:<password>
// The password is hashed before sending: SHA256(SHA256(password) + nonce).
type UserPassClient struct {
	UserID   string
	Password string // plaintext, will be hashed
}

func (a *UserPassClient) Type() Type { return TypeUserPass }

// Respond computes SHA256(SHA256(password) + nonce) and prepends the user ID.
// Wire: [idLen:1][userid:N][hash:32]
func (a *UserPassClient) Respond(challenge []byte) ([]byte, error) {
	// First hash the password
	pwHash := sha256.Sum256([]byte(a.Password))
	// Then hash with nonce
	h := sha256.New()
	h.Write(pwHash[:])
	h.Write(challenge)
	sig := h.Sum(nil)

	idBytes := []byte(a.UserID)
	if len(idBytes) > 255 {
		return nil, fmt.Errorf("userpass: userid too long: %d", len(idBytes))
	}
	resp := make([]byte, 1+len(idBytes)+sha256.Size)
	resp[0] = byte(len(idBytes))
	copy(resp[1:], idBytes)
	copy(resp[1+len(idBytes):], sig)
	return resp, nil
}

// UserPassServer verifies user/password auth with stored SHA256 hashes.
// Server config format: userpass:<userid>:<password_sha256_hex>;<userid2>:<sha256_hex>
type UserPassServer struct {
	// Users maps user ID → SHA256 hash of password (raw 32 bytes).
	Users map[string][sha256.Size]byte
}

func (a *UserPassServer) Type() Type { return TypeUserPass }

func (a *UserPassServer) GenerateChallenge() ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// VerifyResponse parses [idLen:1][userid:N][hash:32] and verifies SHA256(stored_pw_hash + nonce).
func (a *UserPassServer) VerifyResponse(_ common.ClientID, challenge, response []byte) error {
	if len(response) < 1 {
		return fmt.Errorf("userpass: empty response")
	}
	idLen := int(response[0])
	if len(response) < 1+idLen+sha256.Size {
		return fmt.Errorf("userpass: response too short")
	}

	userID := string(response[1 : 1+idLen])
	clientHash := response[1+idLen : 1+idLen+sha256.Size]

	storedPwHash, ok := a.Users[userID]
	if !ok {
		return fmt.Errorf("userpass: unknown user %q", userID)
	}

	// Compute SHA256(stored_pw_hash + nonce) and compare
	h := sha256.New()
	h.Write(storedPwHash[:])
	h.Write(challenge)
	expected := h.Sum(nil)

	if subtle.ConstantTimeCompare(clientHash, expected) != 1 {
		return fmt.Errorf("userpass: verification failed for user %q", userID)
	}
	return nil
}

// HashPassword computes SHA256 of a plaintext password and returns hex string.
// Utility for generating server config values.
func HashPassword(password string) string {
	h := sha256.Sum256([]byte(password))
	return hex.EncodeToString(h[:])
}
