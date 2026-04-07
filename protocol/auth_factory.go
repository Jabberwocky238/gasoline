package protocol

import "fmt"

// NewServerAuth creates a ServerAuthenticator by name.
func NewServerAuth(authType, secret string) (ServerAuthenticator, error) {
	switch authType {
	case "noauth":
		return &NoAuthServer{}, nil
	case "hmac":
		if secret == "" {
			return nil, fmt.Errorf("HMAC auth requires a secret")
		}
		secretBytes := []byte(secret)
		return &HMACAuthServer{
			LookupSecret: func(_ [16]byte) ([]byte, error) {
				return secretBytes, nil
			},
		}, nil
	case "userpass":
		return &UserPassAuthServer{
			LookupPassword: func(_ string) (string, error) {
				return "", fmt.Errorf("no password store configured")
			},
		}, nil
	default:
		return nil, fmt.Errorf("unknown auth type: %s", authType)
	}
}

// NewClientAuth creates a ClientAuthenticator by name.
func NewClientAuth(authType, secret, username, password string) (ClientAuthenticator, error) {
	switch authType {
	case "noauth":
		return &NoAuthClient{}, nil
	case "hmac":
		if secret == "" {
			return nil, fmt.Errorf("HMAC auth requires a secret")
		}
		return &HMACAuthClient{Secret: []byte(secret)}, nil
	case "userpass":
		if username == "" || password == "" {
			return nil, fmt.Errorf("UserPass auth requires username and password")
		}
		return &UserPassAuthClient{Username: username, Password: password}, nil
	default:
		return nil, fmt.Errorf("unknown auth type: %s", authType)
	}
}
