package operator

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jabberwocky238/gasoline/cmd/operator/device/consensus"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/noise"
	"gopkg.in/yaml.v3"
)

// VNetFile is one parsed vnet config file (PRD §4.4). One file == one vnet.
// Version orders competing definitions across operators: version-greatest wins
// (PRD §4.4). Bump it whenever the file changes.
type VNetFile struct {
	VNI      uint32        `yaml:"vni"`
	Version  uint64        `yaml:"version"`
	Segments []SegmentYAML `yaml:"segments"`
	Keys     []KeyYAML     `yaml:"keys"`
}

// SegmentYAML is one subnet + its allocatable pool.
type SegmentYAML struct {
	CIDR     string   `yaml:"cidr"`
	Pool     string   `yaml:"pool"`
	Reserved []string `yaml:"reserved"`
}

// KeyYAML is one authorized client key, optionally pinned to a fixed IP and/or
// restricted to a set of segments.
type KeyYAML struct {
	PubKey          string   `yaml:"pubkey"`
	AllowedSegments []string `yaml:"allowed_segments"`
	StaticIP        string   `yaml:"static_ip"`
}

// LoadVNetDir reads every *.yaml / *.yml in dir as a vnet definition, sorted by
// filename for deterministic ordering. A duplicate VNI across files is an
// error.
func LoadVNetDir(dir string) ([]*VNetFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("vnet dir %q: %w", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext == ".yaml" || ext == ".yml" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var out []*VNetFile
	seen := make(map[uint32]string)
	for _, name := range names {
		path := filepath.Join(dir, name)
		vf, err := LoadVNetFile(path)
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[vf.VNI]; dup {
			return nil, fmt.Errorf("vnet %d defined in both %q and %q", vf.VNI, prev, name)
		}
		seen[vf.VNI] = name
		out = append(out, vf)
	}
	return out, nil
}

// LoadVNetFile parses and validates one vnet file.
func LoadVNetFile(path string) (*VNetFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	var vf VNetFile
	if err := yaml.Unmarshal(b, &vf); err != nil {
		return nil, fmt.Errorf("parse %q: %w", path, err)
	}
	if err := vf.validate(); err != nil {
		return nil, fmt.Errorf("%q: %w", path, err)
	}
	return &vf, nil
}

// validate checks structural constraints (Pool ⊆ CIDR, well-formed keys) that
// don't need the FSM. The FSM re-validates Pool ⊆ CIDR at apply time; catching
// it here gives a file:line-quality error at load.
func (vf *VNetFile) validate() error {
	if len(vf.Segments) == 0 {
		return fmt.Errorf("vnet %d: no segments", vf.VNI)
	}
	for i, s := range vf.Segments {
		cidr, err := netip.ParsePrefix(s.CIDR)
		if err != nil {
			return fmt.Errorf("segment %d: bad cidr %q: %w", i, s.CIDR, err)
		}
		pool, err := netip.ParsePrefix(s.Pool)
		if err != nil {
			return fmt.Errorf("segment %d: bad pool %q: %w", i, s.Pool, err)
		}
		if !prefixWithin(cidr, pool) {
			return fmt.Errorf("segment %d: pool %s not within cidr %s", i, pool, cidr)
		}
		for _, r := range s.Reserved {
			if _, err := netip.ParseAddr(r); err != nil {
				return fmt.Errorf("segment %d: bad reserved addr %q: %w", i, r, err)
			}
		}
	}
	for i, k := range vf.Keys {
		if _, err := decodeKeyPub(k.PubKey); err != nil {
			return fmt.Errorf("key %d: %w", i, err)
		}
		if k.StaticIP != "" {
			if _, err := netip.ParseAddr(k.StaticIP); err != nil {
				return fmt.Errorf("key %d: bad static_ip %q: %w", i, k.StaticIP, err)
			}
		}
		for _, seg := range k.AllowedSegments {
			if _, err := netip.ParsePrefix(seg); err != nil {
				return fmt.Errorf("key %d: bad allowed_segment %q: %w", i, seg, err)
			}
		}
	}
	return nil
}

// ToUpsert converts the parsed file into a Raft VNetUpsert command (PRD §4.4):
// the full vnet definition — segments (with pool/reserved) and the key table —
// plus the file's Version for ordering. Assumes validate() already passed.
func (vf *VNetFile) ToUpsert() (*consensus.VNetUpsert, error) {
	up := &consensus.VNetUpsert{
		VNI:     protocol.VNI_Ty(vf.VNI),
		Version: vf.Version,
	}
	for _, s := range vf.Segments {
		cidr, err := netip.ParsePrefix(s.CIDR)
		if err != nil {
			return nil, err
		}
		pool, err := netip.ParsePrefix(s.Pool)
		if err != nil {
			return nil, err
		}
		seg := consensus.Segment{CIDR: cidr, Pool: pool}
		for _, r := range s.Reserved {
			addr, err := netip.ParseAddr(r)
			if err != nil {
				return nil, err
			}
			seg.Reserved = append(seg.Reserved, addr)
		}
		up.Segments = append(up.Segments, seg)
	}
	for _, k := range vf.Keys {
		pub, err := decodeKeyPub(k.PubKey)
		if err != nil {
			return nil, err
		}
		grant := consensus.KeyGrant{VNI: protocol.VNI_Ty(vf.VNI), PubKey: pub}
		for _, seg := range k.AllowedSegments {
			p, err := netip.ParsePrefix(seg)
			if err != nil {
				return nil, err
			}
			grant.AllowedSeg = append(grant.AllowedSeg, p)
		}
		if k.StaticIP != "" {
			ip, err := netip.ParseAddr(k.StaticIP)
			if err != nil {
				return nil, err
			}
			grant.StaticIP = ip
		}
		up.AuthKeys = append(up.AuthKeys, grant)
	}
	// Guarantee a non-nil AuthKeys so the FSM replaces (not merges) the table
	// even when the file lists zero keys.
	if up.AuthKeys == nil {
		up.AuthKeys = []consensus.KeyGrant{}
	}
	return up, nil
}

// ToStaticVNet converts the file to the pre-consensus StaticOperatorVNetConfig
// (used when Raft is not enabled). CIDR is the first segment's CIDR;
// AuthorizedKeys is every key; PresetKeyMap is the keys that pin a static IP.
func (vf *VNetFile) ToStaticVNet() (StaticOperatorVNetConfig, error) {
	cfg := StaticOperatorVNetConfig{
		VNI:            protocol.VNI_Ty(vf.VNI),
		CIDR:           vf.Segments[0].CIDR,
		AuthorizedKeys: make(map[noise.PublicKey]struct{}),
		PresetKeyMap:   make(map[noise.PublicKey]netip.Prefix),
	}
	for _, k := range vf.Keys {
		pub, err := decodeKeyPub(k.PubKey)
		if err != nil {
			return StaticOperatorVNetConfig{}, err
		}
		cfg.AuthorizedKeys[pub] = struct{}{}
		if k.StaticIP != "" {
			ip, _ := netip.ParseAddr(k.StaticIP)
			cfg.PresetKeyMap[pub] = netip.PrefixFrom(ip, ip.BitLen())
		}
	}
	return cfg, nil
}

// decodeKeyPub decodes a base64 32-byte public key.
func decodeKeyPub(s string) (noise.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return noise.PublicKey{}, fmt.Errorf("pubkey %q: invalid base64: %w", s, err)
	}
	return noise.PublicKeyFromSlice(b)
}

// prefixWithin reports whether inner is fully contained by outer.
func prefixWithin(outer, inner netip.Prefix) bool {
	if outer.Addr().Is4() != inner.Addr().Is4() {
		return false
	}
	if inner.Bits() < outer.Bits() {
		return false
	}
	return outer.Contains(inner.Masked().Addr())
}
