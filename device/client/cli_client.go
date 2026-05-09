package client

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/common/config"
	"github.com/jabberwocky238/gasoline/protocol"
)

func isFlagSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

type ClientConfig struct {
	Endpoint   string
	Transport  string
	AuthStr    string
	VNI        protocol.VNI_Ty
	CID        protocol.CID_Ty
	TUNName    string
	Socks5Port int

	Logger *log.Logger
}

// RegisterClientFlags registers all client CLI flags on the given FlagSet.
// Returns a function that resolves flags + config file into ClientConfig.
func RegisterClientFlags(fs *flag.FlagSet) func() *ClientConfig {
	configFile := fs.String("c", "", "config file path (YAML)")
	endpoint := fs.String("endpoint", "", "server address (required)")
	transportType := fs.String("transport", "quic", "transport type: tcp, tls, udp, quic")
	authStr := fs.String("auth", "noauth", "auth config string")
	vniStr := fs.String("vni", "", "Network Identifier (decimal, e.g. 200)")
	cidStr := fs.String("cid", "", "Presigned Client ID")
	tunName := fs.String("tun-name", "", "TUN device name")
	socks5Port := fs.Int("quick-socks5", 0, "SOCKS5 proxy port (0=disabled, must be >1024)")

	return func() *ClientConfig {
		if *configFile != "" {
			cfg, err := config.LoadConfig(*configFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Config: %v\n", err)
				os.Exit(1)
			}
			if cfg.Endpoint != "" && !isFlagSet(fs, "endpoint") {
				*endpoint = cfg.Endpoint
			}
			if cfg.Transport != "" && !isFlagSet(fs, "transport") {
				*transportType = cfg.Transport
			}
			if cfg.Auth != "" && !isFlagSet(fs, "auth") {
				*authStr = cfg.Auth
			}
			if cfg.VNet != 0 && !isFlagSet(fs, "vni") {
				*vniStr = strconv.FormatUint(cfg.VNet, 10)
			}
			if cfg.TUNName != "" && !isFlagSet(fs, "tun-name") {
				*tunName = cfg.TUNName
			}
		}

		if *endpoint == "" {
			fmt.Fprintln(os.Stderr, "--endpoint is required")
			os.Exit(1)
		}

		if *vniStr == "" {
			fmt.Fprintln(os.Stderr, "--vni is required (must match one of the operator's configured VNIs)")
			os.Exit(1)
		}
		vni, err := common.ParseVNI(*vniStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid VNI %q: %v\n", *vniStr, err)
			os.Exit(1)
		}
		if vni == 0 {
			fmt.Fprintln(os.Stderr, "--vni must be non-zero")
			os.Exit(1)
		}

		if *socks5Port != 0 && *socks5Port <= 1024 {
			fmt.Fprintf(os.Stderr, "--quick-socks5 port must be > 1024, got %d\n", *socks5Port)
			os.Exit(1)
		}

		cid, err := resolveCID(*cidStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid --cid %q: %v\n", *cidStr, err)
			os.Exit(1)
		}
		if (cid == common.CID{}) {
			fmt.Fprintln(os.Stderr, "--cid must be non-zero (omit the flag to auto-generate one)")
			os.Exit(1)
		}

		return &config.ClientConfig{
			Endpoint:   *endpoint,
			Transport:  *transportType,
			AuthStr:    *authStr,
			VNI:        vni,
			CID:        cid,
			TUNName:    *tunName,
			Socks5Port: *socks5Port,
		}
	}
}

// resolveVMAC parses a MAC-formatted address (e.g. "02:00:00:aa:bb:cc"
// or "020000aabbcc") or generates a random locally-administered one if empty.
func resolveVMAC(s string) (common.VMAC, error) {
	var v common.VMAC
	if s == "" {
		if _, err := rand.Read(v[:]); err != nil {
			return v, err
		}
		v[0] = (v[0] & 0xFE) | 0x02 // unicast + locally-administered
		return v, nil
	}
	hexStr := strings.ReplaceAll(strings.ReplaceAll(s, ":", ""), "-", "")
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return v, err
	}
	if len(b) != common.VMACLen {
		return v, fmt.Errorf("must be %d bytes, got %d", common.VMACLen, len(b))
	}
	copy(v[:], b)
	return v, nil
}
