package protocol

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

const saltSize = 32

// --- Client ---

type UserPassAuthClient struct {
	Username string
	Password string
}

func (a *UserPassAuthClient) Type() HandshakeType { return UserPassAuth }

// Respond: [usernameLen:1][username:N][SHA256(password+salt):32]
func (a *UserPassAuthClient) Respond(challenge []byte) ([]byte, error) {
	h := sha256.New()
	h.Write([]byte(a.Password))
	h.Write(challenge)
	hash := h.Sum(nil)

	uname := []byte(a.Username)
	if len(uname) > 255 {
		return nil, fmt.Errorf("username too long: %d bytes", len(uname))
	}
	resp := make([]byte, 1+len(uname)+sha256.Size)
	resp[0] = byte(len(uname))
	copy(resp[1:], uname)
	copy(resp[1+len(uname):], hash)
	return resp, nil
}

// --- Server ---

type UserPassAuthServer struct {
	LookupPassword func(username string) (password string, err error)
}

func (a *UserPassAuthServer) Type() HandshakeType { return UserPassAuth }

func (a *UserPassAuthServer) GenerateChallenge() ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

func (a *UserPassAuthServer) VerifyResponse(_ [16]byte, challenge, response []byte) error {
	if len(response) < 1 {
		return fmt.Errorf("empty response")
	}
	unameLen := int(response[0])
	if len(response) < 1+unameLen+sha256.Size {
		return fmt.Errorf("response too short")
	}
	username := string(response[1 : 1+unameLen])
	clientHash := response[1+unameLen : 1+unameLen+sha256.Size]

	password, err := a.LookupPassword(username)
	if err != nil {
		return fmt.Errorf("lookup user: %w", err)
	}

	h := sha256.New()
	h.Write([]byte(password))
	h.Write(challenge)
	expected := h.Sum(nil)

	if subtle.ConstantTimeCompare(clientHash, expected) != 1 {
		return fmt.Errorf("password verification failed")
	}
	return nil
}
