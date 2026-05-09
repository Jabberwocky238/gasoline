package client

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/jabberwocky238/gasoline/protocol"
)

// ClientConfig is the resolved CLI configuration. The TUN/SOCKS5/etc.
// fields that used to live here are gone alongside the now-deleted
// vtep + tun-bridge data plane; the client's job is just to dial and
// keep the transport up.
type ClientConfig struct {
	Endpoint  string
	Transport string
	AuthStr   string
	VNI       protocol.VNI_Ty
	CID       protocol.CID_Ty

	Logger *log.Logger
}

func isFlagSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// RegisterClientFlags registers all client CLI flags on the given FlagSet.
// Returns a function that resolves the parsed flags into a *ClientConfig.
func RegisterClientFlags(fs *flag.FlagSet) func() *ClientConfig {
	endpoint := fs.String("endpoint", "", "server address (required)")
	transportType := fs.String("transport", "quic", "transport type: tcp, udp, quic")
	authStr := fs.String("auth", "noauth", "auth config string")
	vniStr := fs.String("vni", "", "VNI (decimal, e.g. 200)")
	cidStr := fs.String("cid", "", "preassigned client ID (16 hex chars; auto-generated if empty)")
	_ = isFlagSet // kept exported helper for callers that mix config sources

	return func() *ClientConfig {
		if *endpoint == "" {
			fmt.Fprintln(os.Stderr, "--endpoint is required")
			os.Exit(1)
		}
		if *vniStr == "" {
			fmt.Fprintln(os.Stderr, "--vni is required")
			os.Exit(1)
		}
		vniU, err := strconv.ParseUint(*vniStr, 10, 32)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid VNI %q: %v\n", *vniStr, err)
			os.Exit(1)
		}

		cid, err := resolveCID(*cidStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid --cid %q: %v\n", *cidStr, err)
			os.Exit(1)
		}

		return &ClientConfig{
			Endpoint:  *endpoint,
			Transport: *transportType,
			AuthStr:   *authStr,
			VNI:       protocol.VNI_Ty(vniU),
			CID:       cid,
		}
	}
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
