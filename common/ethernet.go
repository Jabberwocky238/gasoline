package common

import "encoding/binary"

// Ethernet frame helpers.
//
// Userspace L2 simulation: the client's TUN reads raw IP packets; we wrap
// them into a fake Ethernet frame so the rest of the data plane (operator,
// VXLAN, remote operator, peer client) only ever sees L2 frames. The real
// OS network stack is not involved in MAC resolution — the client-side
// ARP table is a pure userspace map (see phase-2 work).
//
// Wire layout of a frame emitted by WrapEth:
//   [dstMAC:6][srcMAC:6][ethType:2][payload...]

// WrapEth builds a full Ethernet frame around payload.
// Returns a freshly allocated slice. For hot paths, prefer WriteEthHeader
// into a pre-sized buffer.
func WrapEth(dstMAC, srcMAC VMAC, ethType uint16, payload []byte) []byte {
	out := make([]byte, EthHeaderSize+len(payload))
	copy(out[0:6], dstMAC[:])
	copy(out[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(out[12:14], ethType)
	copy(out[14:], payload)
	return out
}

// WriteEthHeader stamps an Ethernet header at dst[0:14].
// dst must have at least EthHeaderSize bytes of capacity.
func WriteEthHeader(dst []byte, dstMAC, srcMAC VMAC, ethType uint16) {
	_ = dst[EthHeaderSize-1] // bounds hint
	copy(dst[0:6], dstMAC[:])
	copy(dst[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(dst[12:14], ethType)
}

// ParseEth returns (dstMAC, srcMAC, ethType, payload) of an Ethernet frame.
// The returned slices alias into frame — do not mutate.
func ParseEth(frame []byte) (dstMAC, srcMAC VMAC, ethType uint16, payload []byte, ok bool) {
	if len(frame) < EthHeaderSize {
		return
	}
	copy(dstMAC[:], frame[0:6])
	copy(srcMAC[:], frame[6:12])
	ethType = binary.BigEndian.Uint16(frame[12:14])
	payload = frame[EthHeaderSize:]
	ok = true
	return
}

// EtherTypeKeepalive is the EtherType used for client↔operator keepalive frames.
// Picked from the IEEE "local/experimental" range so it cannot collide with
// IPv4, IPv6, or ARP.
//
// Protocol: client emits (dst=00:00:00:00:00:00, src=selfMAC, type=0x88B5,
// payload empty). Operator reflects (dst=clientMAC, src=00:00:00:00:00:00,
// type=0x88B5, payload empty). Keepalive frames never enter the VXLAN plane.
const EtherTypeKeepalive uint16 = 0x88B5

// KeepaliveZeroMAC is the all-zero VMAC used as the "peer" side of a keepalive
// exchange (src on operator replies, dst on client requests).
var KeepaliveZeroMAC = VMAC{}

// IsKeepaliveRequest reports whether frame is a client→operator keepalive
// (dst=all-zero, type=EtherTypeKeepalive). Returns the client's src MAC.
func IsKeepaliveRequest(frame []byte) (srcMAC VMAC, ok bool) {
	dst, src, ethType, _, parsed := ParseEth(frame)
	if !parsed || ethType != EtherTypeKeepalive {
		return VMAC{}, false
	}
	if dst != KeepaliveZeroMAC {
		return VMAC{}, false
	}
	return src, true
}

// IsKeepaliveReply reports whether frame is an operator→client keepalive reply
// for selfMAC (dst=selfMAC, src=all-zero, type=EtherTypeKeepalive).
func IsKeepaliveReply(frame []byte, selfMAC VMAC) bool {
	dst, src, ethType, _, ok := ParseEth(frame)
	if !ok || ethType != EtherTypeKeepalive {
		return false
	}
	return dst == selfMAC && src == KeepaliveZeroMAC
}

// BuildKeepaliveRequest constructs a client→operator keepalive frame.
func BuildKeepaliveRequest(selfMAC VMAC) []byte {
	return WrapEth(KeepaliveZeroMAC, selfMAC, EtherTypeKeepalive, nil)
}

// BuildKeepaliveReply constructs an operator→client keepalive reply frame.
func BuildKeepaliveReply(clientMAC VMAC) []byte {
	return WrapEth(clientMAC, KeepaliveZeroMAC, EtherTypeKeepalive, nil)
}

// EthTypeFromIP picks the EtherType based on an inner IP packet's version nibble.
func EthTypeFromIP(ipPacket []byte) uint16 {
	if len(ipPacket) == 0 {
		return 0
	}
	switch ipPacket[0] >> 4 {
	case 4:
		return EtherTypeIPv4
	case 6:
		return EtherTypeIPv6
	}
	return 0
}
