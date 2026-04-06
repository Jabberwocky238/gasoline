package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

const nonceSize = 32

// --- Client ---

type HMACAuthClient struct {
	Secret []byte
}

func (a *HMACAuthClient) Type() HandshakeType { return HMACAuth }

func (a *HMACAuthClient) Respond(challenge []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, a.Secret)
	mac.Write(challenge)
	return mac.Sum(nil), nil
}

// --- Server ---

type HMACAuthServer struct {
	LookupSecret func(clientID [16]byte) ([]byte, error)
}

func (a *HMACAuthServer) Type() HandshakeType { return HMACAuth }

func (a *HMACAuthServer) GenerateChallenge() ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

func (a *HMACAuthServer) VerifyResponse(clientID [16]byte, challenge, response []byte) error {
	secret, err := a.LookupSecret(clientID)
	if err != nil {
		return fmt.Errorf("lookup secret: %w", err)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(challenge)
	expected := mac.Sum(nil)
	if !hmac.Equal(response, expected) {
		return fmt.Errorf("HMAC verification failed")
	}
	return nil
}
