package auth

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"
)

// NoAuthClient sends VNetID + device fingerprint during handshake.
type NoAuthClient struct {
	VNetID      [16]byte
	Fingerprint []byte
}

func (a *NoAuthClient) Type() Type { return TypeNoAuth }

// Respond sends [vnetID:16][fingerprint] as the auth payload.
func (a *NoAuthClient) Respond(_ []byte) ([]byte, error) {
	payload := make([]byte, 16+len(a.Fingerprint))
	copy(payload[:16], a.VNetID[:])
	copy(payload[16:], a.Fingerprint)
	return payload, nil
}

// NoAuthServer generates a SessionID from fingerprint + timestamp.
type NoAuthServer struct {
	// Populated after VerifyResponse for use in ConfigFunc.
	LastVNetID    [16]byte
	LastSessionID [16]byte
}

func (a *NoAuthServer) Type() Type                        { return TypeNoAuth }
func (a *NoAuthServer) GenerateChallenge() ([]byte, error) { return nil, nil }

// VerifyResponse parses [vnetID:16][fingerprint], generates sessionID = sha256(fingerprint||timestamp)[:16].
func (a *NoAuthServer) VerifyResponse(_ [16]byte, _, response []byte) error {
	if len(response) < 16 {
		return fmt.Errorf("noauth: payload too short: %d", len(response))
	}
	copy(a.LastVNetID[:], response[:16])
	fingerprint := response[16:]

	h := sha256.New()
	h.Write(fingerprint)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(time.Now().UnixNano()))
	h.Write(ts[:])
	sum := h.Sum(nil)
	copy(a.LastSessionID[:], sum[:16])
	return nil
}
