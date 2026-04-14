package common

import (
	"encoding/binary"
	"fmt"
)

// VXLAN-encapsulated data frame wire format (one UDP datagram = one frame):
//
//   [VXLAN header:8][inner Ethernet:14][inner IP packet:N]
//
// VXLAN header layout (RFC 7348):
//   bytes 0-3: flags — high bit of byte 0 set (I flag = VNI valid), rest reserved
//   bytes 4-6: VNI   — 24-bit Virtual Network Identifier
//   byte  7:   reserved
//
// Inner Ethernet:
//   bytes 0-5:   destination MAC = destination ClientID (6B, verbatim)
//   bytes 6-11:  source MAC      = source ClientID      (6B, verbatim)
//   bytes 12-13: EtherType       (0x0800 IPv4 | 0x86DD IPv6)
//
// Forwarding decisions are keyed on (VNI, destination ClientID) — the inner
// IP payload is never inspected by the data plane.

const (
	VxlanHeaderSize = 8
	EthHeaderSize   = 14

	vxlanFlagsValid = 0x08 // I bit — VNI present

	EtherTypeIPv4 = 0x0800
	EtherTypeIPv6 = 0x86DD
)

// DataFrame is a pooled, reusable VXLAN frame buffer.
type DataFrame struct {
	buf       [MaxPacketSize]byte
	VNI       VNI
	EtherType uint16   // 0x0800 (IPv4) or 0x86DD (IPv6)
	Packet    []byte   // slice into buf — inner IP packet
	Size      int      // total wire size
	SrcCID    ClientID // source client MAC, decoded from inner src MAC
	DstCID    ClientID // destination client MAC, decoded from inner dst MAC
}

// Encode writes [VXLAN][Ethernet][IP packet] into the frame's buffer.
// srcClientID / dstClientID are placed verbatim into the inner Ethernet
// source/destination MAC fields. EtherType is derived from the IP version
// nibble of packet[0] (IPv4 → 0x0800, IPv6 → 0x86DD).
func (f *DataFrame) Encode(vni VNI, srcClientID, dstClientID ClientID, packet []byte) []byte {
	version := InnerIPVersion(packet)
	mtu := MTUFor(version)
	if mtu == 0 {
		panic(fmt.Sprintf("dataframe: unknown IP version for packet[0]=0x%02x", packet[0]))
	}
	if len(packet) > mtu {
		panic(fmt.Sprintf("dataframe: inner IPv%d packet %d > mtu %d", version, len(packet), mtu))
	}

	f.VNI = vni
	f.SrcCID = srcClientID
	f.DstCID = dstClientID
	if version == 6 {
		f.EtherType = EtherTypeIPv6
	} else {
		f.EtherType = EtherTypeIPv4
	}

	// VXLAN header
	f.buf[0] = vxlanFlagsValid
	f.buf[1] = 0
	f.buf[2] = 0
	f.buf[3] = 0
	vb := vni.Bytes3()
	f.buf[4] = vb[0]
	f.buf[5] = vb[1]
	f.buf[6] = vb[2]
	f.buf[7] = 0

	// Inner Ethernet: dst MAC, src MAC, ethertype
	copy(f.buf[VxlanHeaderSize:], dstClientID[:])
	copy(f.buf[VxlanHeaderSize+6:], srcClientID[:])
	binary.BigEndian.PutUint16(f.buf[VxlanHeaderSize+12:], f.EtherType)

	// Inner IP packet
	payloadOffset := VxlanHeaderSize + EthHeaderSize
	copy(f.buf[payloadOffset:], packet)

	f.Size = payloadOffset + len(packet)
	f.Packet = f.buf[payloadOffset:f.Size]
	return f.buf[:f.Size]
}

// Decode parses a received VXLAN-encapsulated datagram.
// data is copied into the internal buffer so the caller can reuse their read buffer.
func (f *DataFrame) Decode(data []byte) error {
	if len(data) < VxlanHeaderSize+EthHeaderSize {
		return fmt.Errorf("vxlan frame too short: %d", len(data))
	}
	if len(data) > MaxVxlanPayload {
		return fmt.Errorf("vxlan frame too large: %d > %d", len(data), MaxVxlanPayload)
	}
	f.Size = len(data)
	copy(f.buf[:f.Size], data)

	if f.buf[0]&vxlanFlagsValid == 0 {
		return fmt.Errorf("vxlan: I flag not set")
	}

	f.VNI = VNIFromBytes3([3]byte{f.buf[4], f.buf[5], f.buf[6]})

	// Inner Ethernet: full 6-byte MACs (= ClientIDs) + EtherType
	copy(f.DstCID[:], f.buf[VxlanHeaderSize:VxlanHeaderSize+6])
	copy(f.SrcCID[:], f.buf[VxlanHeaderSize+6:VxlanHeaderSize+12])
	f.EtherType = binary.BigEndian.Uint16(f.buf[VxlanHeaderSize+12:])

	payloadOffset := VxlanHeaderSize + EthHeaderSize
	f.Packet = f.buf[payloadOffset:f.Size]
	return nil
}

// Reset clears the frame for reuse.
func (f *DataFrame) Reset() {
	f.Packet = nil
	f.Size = 0
	f.SrcCID = ClientID{}
	f.DstCID = ClientID{}
	f.EtherType = 0
}
