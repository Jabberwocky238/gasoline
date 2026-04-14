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
//   bytes 0-5:   destination MAC = destination VMAC (6B, verbatim)
//   bytes 6-11:  source MAC      = source VMAC      (6B, verbatim)
//   bytes 12-13: EtherType       (0x0800 IPv4 | 0x86DD IPv6)
//
// Forwarding decisions are keyed on (VNI, destination VMAC) — the inner
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
	SrcMAC    VMAC // source client MAC, decoded from inner src MAC
	DstMAC    VMAC // destination client MAC, decoded from inner dst MAC
}

// EncodeFrame prepends an 8-byte VXLAN header to a pre-built Ethernet
// frame. The caller (client-side VTun, or operator on ingress) is
// responsible for constructing the inner Ethernet header — operator-side
// VXLAN encap never inspects the inner payload.
//
// ethFrame layout: [dstMAC:6][srcMAC:6][ethType:2][payload...]
func (f *DataFrame) EncodeFrame(vni VNI, ethFrame []byte) []byte {
	if len(ethFrame) < EthHeaderSize {
		panic(fmt.Sprintf("dataframe: eth frame too short %d", len(ethFrame)))
	}
	if len(ethFrame) > MaxVxlanPayload {
		panic(fmt.Sprintf("dataframe: eth frame %d > MaxVxlanPayload %d", len(ethFrame), MaxVxlanPayload))
	}

	f.VNI = vni
	copy(f.DstMAC[:], ethFrame[0:6])
	copy(f.SrcMAC[:], ethFrame[6:12])
	f.EtherType = binary.BigEndian.Uint16(ethFrame[12:14])

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

	// Inner Ethernet + payload — verbatim from caller.
	copy(f.buf[VxlanHeaderSize:], ethFrame)

	f.Size = VxlanHeaderSize + len(ethFrame)
	f.Packet = f.buf[VxlanHeaderSize+EthHeaderSize : f.Size]
	return f.buf[:f.Size]
}

// Encode (legacy) constructs an Ethernet frame from (srcMAC, dstMAC, ipPacket)
// then VXLAN-wraps it. Kept for tests/back-compat; new code should build the
// Eth frame upstream and call EncodeFrame.
func (f *DataFrame) Encode(vni VNI, srcVMAC, dstVMAC VMAC, packet []byte) []byte {
	version := InnerIPVersion(packet)
	mtu := MTUFor(version)
	if mtu == 0 {
		panic(fmt.Sprintf("dataframe: unknown IP version for packet[0]=0x%02x", packet[0]))
	}
	if len(packet) > mtu {
		panic(fmt.Sprintf("dataframe: inner IPv%d packet %d > mtu %d", version, len(packet), mtu))
	}
	ethType := EtherTypeIPv4
	if version == 6 {
		ethType = EtherTypeIPv6
	}
	tmpBuf := GetBuffer()
	defer PutBuffer(tmpBuf)
	tmp := (*tmpBuf)[:EthHeaderSize+len(packet)]
	WriteEthHeader(tmp, dstVMAC, srcVMAC, uint16(ethType))
	copy(tmp[EthHeaderSize:], packet)
	return f.EncodeFrame(vni, tmp)
}

// Frame returns the inner Ethernet frame (without VXLAN header) of a
// decoded DataFrame: [dstMAC:6][srcMAC:6][ethType:2][payload].
func (f *DataFrame) Frame() []byte {
	if f.Size < VxlanHeaderSize+EthHeaderSize {
		return nil
	}
	return f.buf[VxlanHeaderSize:f.Size]
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
	copy(f.DstMAC[:], f.buf[VxlanHeaderSize:VxlanHeaderSize+6])
	copy(f.SrcMAC[:], f.buf[VxlanHeaderSize+6:VxlanHeaderSize+12])
	f.EtherType = binary.BigEndian.Uint16(f.buf[VxlanHeaderSize+12:])

	payloadOffset := VxlanHeaderSize + EthHeaderSize
	f.Packet = f.buf[payloadOffset:f.Size]
	return nil
}

// Reset clears the frame for reuse.
func (f *DataFrame) Reset() {
	f.Packet = nil
	f.Size = 0
	f.SrcMAC = VMAC{}
	f.DstMAC = VMAC{}
	f.EtherType = 0
}
