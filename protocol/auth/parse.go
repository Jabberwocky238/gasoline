package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// ParseServerAuth parses a server auth config string and returns a ServerAuthenticator.
//
// Formats:
//
//	"noauth"
//	"hmac:<id>:<secret>;<id2>:<secret2>"
//	"userpass:<userid>:<password_sha256_hex>;<userid2>:<sha256_hex>"
func ParseServerAuth(raw string) (ServerAuthenticator, error) {
	if raw == "" || raw == "noauth" {
		return &NoAuthServer{}, nil
	}

	if strings.HasPrefix(raw, "hmac:") {
		body := raw[len("hmac:"):]
		secrets := make(map[string][]byte)
		for _, entry := range strings.Split(body, ";") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			parts := strings.SplitN(entry, ":", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("hmac: invalid entry %q (expected id:secret)", entry)
			}
			secrets[parts[0]] = []byte(parts[1])
		}
		if len(secrets) == 0 {
			return nil, fmt.Errorf("hmac: no id:secret pairs")
		}
		return &HMACServer{Secrets: secrets}, nil
	}

	if strings.HasPrefix(raw, "userpass:") {
		body := raw[len("userpass:"):]
		users := make(map[string][sha256.Size]byte)
		for _, entry := range strings.Split(body, ";") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			parts := strings.SplitN(entry, ":", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("userpass: invalid entry %q (expected userid:sha256hex)", entry)
			}
			hashBytes, err := hex.DecodeString(parts[1])
			if err != nil || len(hashBytes) != sha256.Size {
				return nil, fmt.Errorf("userpass: invalid sha256 for user %q", parts[0])
			}
			var h [sha256.Size]byte
			copy(h[:], hashBytes)
			users[parts[0]] = h
		}
		if len(users) == 0 {
			return nil, fmt.Errorf("userpass: no userid:sha256 pairs")
		}
		return &UserPassServer{Users: users}, nil
	}

	return nil, fmt.Errorf("unknown auth format: %q", raw)
}

// ParseClientAuth parses a client auth config string and returns a ClientAuthenticator.
//
// Formats:
//
//	"noauth"
//	"hmac:<id>:<secret>"
//	"userpass:<userid>:<password>"
func ParseClientAuth(raw string, fingerprint []byte) (ClientAuthenticator, error) {
	if raw == "" || raw == "noauth" {
		return &NoAuthClient{Fingerprint: fingerprint}, nil
	}

	if strings.HasPrefix(raw, "hmac:") {
		body := raw[len("hmac:"):]
		parts := strings.SplitN(body, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("hmac: invalid format %q (expected hmac:id:secret)", raw)
		}
		return &HMACClient{ID: parts[0], Secret: []byte(parts[1])}, nil
	}

	if strings.HasPrefix(raw, "userpass:") {
		body := raw[len("userpass:"):]
		parts := strings.SplitN(body, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("userpass: invalid format %q (expected userpass:userid:password)", raw)
		}
		return &UserPassClient{UserID: parts[0], Password: parts[1]}, nil
	}

	return nil, fmt.Errorf("unknown auth format: %q", raw)
}
