package common

import (
	"encoding/hex"
	"fmt"
	"strconv"
)

const (
	SessionIDLen    = 16
	OperatorUUIDLen = 16
	VMACLen         = 6 // virtual MAC; the client's inner Ethernet address
)

// VMAC is the client's 6-byte virtual MAC address — the forwarding identity
// throughout the L2 overlay. Should be a locally-administered unicast address
// (bit 0 of byte 0 clear, bit 1 set) but this is not enforced here.
type VMAC = [VMACLen]byte

// EthBroadcastMAC is FF:FF:FF:FF:FF:FF — used for ARP requests.
var EthBroadcastMAC = VMAC{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

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

// MTU budget — dual stack.
//
// We allow different inner-IP sizes per address family so that L4 payload
// space stays close across stacks while the whole VXLAN-encapsulated frame
// still fits in a 1500-byte underlay:
//
//	Underlay MTU:              1500
//	- Outer Ethernet:            14
//	- Outer IP (IPv4):           20
//	- Outer UDP:                  8
//	- VXLAN header:               8
//	- Inner Ethernet:            14
//	─────────────────────────────────
//	- Available for inner IP:  1436
//
// Conservative per-family inner IP caps:
//
//	IPv4 packet (20B hdr): ≤ 1420  →  L4 payload ≤ 1400
//	IPv6 packet (40B hdr): ≤ 1400  →  L4 payload ≤ 1360
//
// The TUN device is configured with MTU = TunMTUv4 (1420); IPv6 senders
// must self-limit (or rely on PMTUD) to stay under TunMTUv6 (1400).
const (
	TunMTUv4 = 1420
	TunMTUv6 = 1400

	// TunMTU is the Linux TUN interface MTU (single value, must cover
	// the larger of the two family caps).
	TunMTU = TunMTUv4

	// VxlanOverhead = VXLAN header (8) + inner Ethernet (14).
	VxlanOverhead = 8 + 14

	// MaxVxlanPayload is the maximum UDP datagram payload we will ever emit
	// on the inter-operator data plane (sized to the larger family cap).
	MaxVxlanPayload = 1500
)

// MTUFor returns the per-family inner-IP cap.
func MTUFor(version int) int {
	switch version {
	case 4:
		return TunMTUv4
	case 6:
		return TunMTUv6
	}
	return 0
}
