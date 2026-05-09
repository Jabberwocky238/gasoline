package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/jabberwocky238/gasoline/device/client"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/sirupsen/logrus"
)

// Recognized parameter keys for RegisterClientCLIParam.
const (
	ParamEndpoint  = "endpoint"
	ParamTransport = "transport"
	ParamAuth      = "auth"
	ParamVNI       = "vni"
	ParamCID       = "cid"
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
		case ParamEndpoint, ParamTransport, ParamAuth, ParamVNI, ParamCID, ParamTUN, ParamLogLevel:
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
	case "tcp", "udp", "quic", "tls":
	default:
		return nil, fmt.Errorf("transport %q: must be tcp|udp|quic|tls", transport)
	}

	authStr := lastOr(params[ParamAuth], "noauth")

	vniStr := lastOr(params[ParamVNI], "")
	if vniStr == "" {
		return nil, fmt.Errorf("--vni is required")
	}
	vniU, err := strconv.ParseUint(strings.TrimSpace(vniStr), 10, 32)
	if err != nil {
		return nil, fmt.Errorf("vni %q: %v", vniStr, err)
	}

	cid, err := resolveCID(lastOr(params[ParamCID], ""))
	if err != nil {
		return nil, fmt.Errorf("cid: %w", err)
	}

	tunName := lastOr(params[ParamTUN], "")

	lvl, err := logrus.ParseLevel(strings.TrimSpace(lastOr(params[ParamLogLevel], "info")))
	if err != nil {
		return nil, fmt.Errorf("log-level: %w", err)
	}

	return &client.StaticClientConfig{
		Endpoint:  endpoint,
		Transport: transport,
		AuthStr:   authStr,
		VNI:       protocol.VNI_Ty(vniU),
		CID:       cid,
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

// resolveCID parses a hex-encoded CID or generates a random one if s is empty.
func resolveCID(s string) (protocol.CID_Ty, error) {
	var cid protocol.CID_Ty
	if s == "" {
		if _, err := rand.Read(cid[:]); err != nil {
			return cid, err
		}
		return cid, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return cid, err
	}
	if len(b) != len(cid) {
		return cid, fmt.Errorf("must be %d bytes, got %d", len(cid), len(b))
	}
	copy(cid[:], b)
	return cid, nil
}
