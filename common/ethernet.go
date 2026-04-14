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
