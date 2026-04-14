package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/jabberwocky238/gasoline/common"
)

const nonceSize = 32

// HMACClient authenticates with a pre-shared ID and secret.
// Auth field format: hmac:<id>:<secret>
type HMACClient struct {
	ID     string
	Secret []byte
}

func (a *HMACClient) Type() Type { return TypeHMAC }

// Respond computes HMAC-SHA256(secret, nonce) and prepends the ID.
// Wire: [idLen:1][id:N][mac:32]
func (a *HMACClient) Respond(challenge []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, a.Secret)
	mac.Write(challenge)
	sig := mac.Sum(nil)

	idBytes := []byte(a.ID)
	if len(idBytes) > 255 {
		return nil, fmt.Errorf("hmac: id too long: %d", len(idBytes))
	}
	resp := make([]byte, 1+len(idBytes)+sha256.Size)
	resp[0] = byte(len(idBytes))
	copy(resp[1:], idBytes)
	copy(resp[1+len(idBytes):], sig)
	return resp, nil
}

// HMACServer verifies HMAC auth with a set of known ID→secret pairs.
// Server config format: hmac:<id>:<secret>;<id2>:<secret2>
type HMACServer struct {
	// Secrets maps client ID string → secret bytes.
	Secrets map[string][]byte
}

func (a *HMACServer) Type() Type { return TypeHMAC }

func (a *HMACServer) GenerateChallenge() ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// VerifyResponse parses [idLen:1][id:N][mac:32] and verifies HMAC.
func (a *HMACServer) VerifyResponse(_ common.VMAC, challenge, response []byte) error {
	if len(response) < 1 {
		return fmt.Errorf("hmac: empty response")
	}
	idLen := int(response[0])
	if len(response) < 1+idLen+sha256.Size {
		return fmt.Errorf("hmac: response too short")
	}

	id := string(response[1 : 1+idLen])
	clientMAC := response[1+idLen : 1+idLen+sha256.Size]

	secret, ok := a.Secrets[id]
	if !ok {
		return fmt.Errorf("hmac: unknown id %q", id)
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(challenge)
	expected := mac.Sum(nil)
	if !hmac.Equal(clientMAC, expected) {
		return fmt.Errorf("hmac: verification failed for id %q", id)
	}
	return nil
}
