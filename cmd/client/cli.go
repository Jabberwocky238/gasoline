package main

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/jabberwocky238/gasoline/cmd/client/device"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/noise"
	"github.com/sirupsen/logrus"
)

// Recognized parameter keys for RegisterClientCLIParam.
const (
	ParamEndpoint  = "endpoint"
	ParamTransport = "transport"
	ParamVNI       = "vni"
	ParamKey       = "key"        // client static private key (base64); generated if empty
	ParamServerPub = "server-pub" // operator static public key (base64), required
	ParamTUN       = "tun"
	ParamLogLevel  = "log-level"
)

// RegisterClientCLIParam turns a parameter map (as produced by main.go's
// CLI parser) into a *client.StaticClientConfig. Single-valued keys
// take the last entry of their slice. Missing optional keys fall back
// to documented defaults; missing required keys are an error.
func RegisterClientCLIParam(params map[string][]string) (*client.StaticClientConfig, error) {
	for k := range params {
		switch k {
		case ParamEndpoint, ParamTransport, ParamVNI, ParamKey, ParamServerPub, ParamTUN, ParamLogLevel:
		default:
			return nil, fmt.Errorf("unknown parameter %q", k)
		}
	}

	endpoint := lastOr(params[ParamEndpoint], "")
	if endpoint == "" {
		return nil, fmt.Errorf("--endpoint is required")
	}

	transport := lastOr(params[ParamTransport], "quic")
	switch transport {
	case "udp", "quic":
	default:
		return nil, fmt.Errorf("transport %q: must be udp|quic", transport)
	}

	vniStr := lastOr(params[ParamVNI], "")
	if vniStr == "" {
		return nil, fmt.Errorf("--vni is required")
	}
	vniU, err := strconv.ParseUint(strings.TrimSpace(vniStr), 10, 32)
	if err != nil {
		return nil, fmt.Errorf("vni %q: %v", vniStr, err)
	}

	priv, pub, err := resolveClientKey(lastOr(params[ParamKey], ""))
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}

	serverPubStr := lastOr(params[ParamServerPub], "")
	if serverPubStr == "" {
		return nil, fmt.Errorf("--server-pub is required (operator static public key, base64)")
	}
	serverPub, err := decodePub(serverPubStr)
	if err != nil {
		return nil, fmt.Errorf("server-pub: %w", err)
	}

	tunName := lastOr(params[ParamTUN], "")

	lvl, err := logrus.ParseLevel(strings.TrimSpace(lastOr(params[ParamLogLevel], "info")))
	if err != nil {
		return nil, fmt.Errorf("log-level: %w", err)
	}

	return &client.StaticClientConfig{
		Endpoint:  endpoint,
		Transport: transport,
		VNI:       protocol.VNI_Ty(vniU),
		Priv:      priv,
		Pub:       pub,
		ServerPub: serverPub,
		TUNName:   tunName,
		LogLevel:  lvl,
	}, nil
}

func lastOr(vs []string, fallback string) string {
	if len(vs) == 0 {
		return fallback
	}
	return vs[len(vs)-1]
}

// resolveClientKey decodes a base64 private key, or generates a fresh pair
// when s is empty. Returns the private and derived public key.
func resolveClientKey(s string) (noise.PrivateKey, noise.PublicKey, error) {
	if s == "" {
		return noise.GenerateKey()
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return noise.PrivateKey{}, noise.PublicKey{}, fmt.Errorf("invalid base64: %w", err)
	}
	priv, err := noise.PrivateKeyFromSlice(b)
	if err != nil {
		return noise.PrivateKey{}, noise.PublicKey{}, err
	}
	return priv, priv.Public(), nil
}

// decodePub decodes a base64-encoded 32-byte public key.
func decodePub(s string) (noise.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return noise.PublicKey{}, fmt.Errorf("invalid base64: %w", err)
	}
	return noise.PublicKeyFromSlice(b)
}
