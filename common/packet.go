package common

import (
	"encoding/hex"
	"fmt"
	"strconv"
)

const (
	SessionIDLen    = 16
	OperatorUUIDLen = 16
)

// VNI is a 24-bit VXLAN Network Identifier.
// Only the lower 24 bits are used; values 0x01000000 and above are invalid.
type VNI uint32

const (
	VNIMax VNI = 0xFFFFFF
)

// Valid reports whether the VNI fits in 24 bits.
func (v VNI) Valid() bool {
	return v <= VNIMax
}

// String renders a VNI as a 6-digit hex, e.g. "0001a2".
func (v VNI) String() string {
	return fmt.Sprintf("%06x", uint32(v))
}

// Bytes3 returns the VNI as the 3-byte big-endian wire representation
// used in the VXLAN header (most-significant byte first).
func (v VNI) Bytes3() [3]byte {
	return [3]byte{byte(v >> 16), byte(v >> 8), byte(v)}
}

// VNIFromBytes3 reconstructs a VNI from its 3-byte big-endian wire form.
func VNIFromBytes3(b [3]byte) VNI {
	return VNI(uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]))
}

// ParseVNI accepts decimal ("1234") or hex ("0x1a2b3c" / "1a2b3c") input.
func ParseVNI(s string) (VNI, error) {
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		n, err := strconv.ParseUint(s[2:], 16, 32)
		if err != nil {
			return 0, err
		}
		if VNI(n) > VNIMax {
			return 0, fmt.Errorf("vni out of range: %s", s)
		}
		return VNI(n), nil
	}
	if n, err := strconv.ParseUint(s, 10, 32); err == nil {
		if VNI(n) > VNIMax {
			return 0, fmt.Errorf("vni out of range: %s", s)
		}
		return VNI(n), nil
	}
	// Fallback: try hex without prefix
	b, err := hex.DecodeString(s)
	if err != nil || len(b) > 3 {
		return 0, fmt.Errorf("invalid vni: %q", s)
	}
	var padded [3]byte
	copy(padded[3-len(b):], b)
	return VNIFromBytes3(padded), nil
}

// MTU budget.
//
// Client TUN MTU is fixed at 1400 bytes. This leaves headroom on a standard
// 1500-byte underlay for any encapsulation we add on top:
//
//	Underlay MTU:              1500
//	- Outer Ethernet:            14
//	- Outer IP (IPv4):           20
//	- Outer UDP:                  8
//	- VXLAN header:               8
//	- Inner Ethernet:            14
//	─────────────────────────────────
//	- Available for inner IP:  1436  (≥ our 1400 TUN MTU)
//
// Any packet handed to the operator data plane that exceeds TunMTU is dropped.
const (
	TunMTU = 1400

	// VxlanOverhead = VXLAN header (8) + inner Ethernet (14).
	VxlanOverhead = 8 + 14

	// MaxVxlanPayload is the maximum UDP datagram payload we will ever emit
	// on the inter-operator data plane.
	MaxVxlanPayload = TunMTU + VxlanOverhead // 1422
)
