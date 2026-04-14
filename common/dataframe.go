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
// Inner Ethernet MAC layout:
//   byte  0:   (VNI[0] & 0xFE) | 0x02  — unicast + locally-administered
//   bytes 1-2: lower 16 bits of VNI verbatim
//   bytes 3-5: first 3 bytes of the peer's SessionID

const (
	maxDatagramSize = 65535

	VxlanHeaderSize = 8
	EthHeaderSize   = 14

	vxlanFlagsValid = 0x08 // I bit — VNI present

	innerEthType = 0x0800 // IPv4
)

// MACFor synthesises the inner Ethernet MAC for a (VNI, SessionID) pair.
func MACFor(vni VNI, sessionID [16]byte) [6]byte {
	v := vni.Bytes3()
	return [6]byte{
		(v[0] & 0xFE) | 0x02, // unicast + locally-administered
		v[1],
		v[2],
		sessionID[0],
		sessionID[1],
		sessionID[2],
	}
}

// DataFrame is a pooled, reusable VXLAN frame buffer.
type DataFrame struct {
	buf    [maxDatagramSize]byte
	VNI    VNI
	Packet []byte  // slice into buf — inner IP packet
	Size   int     // total wire size
	SrcSID [3]byte // first 3 bytes of source SessionID, decoded from inner src MAC
	DstSID [3]byte // first 3 bytes of destination SessionID, decoded from inner dst MAC
}

// Encode writes [VXLAN][Ethernet][IP packet] into the frame's buffer.
// srcSessionID / dstSessionID are the originating and target client session IDs —
// their first 3 bytes are embedded in the inner Ethernet src/dst MACs.
// Panics if packet exceeds TunMTU.
func (f *DataFrame) Encode(vni VNI, srcSessionID, dstSessionID [16]byte, packet []byte) []byte {
	if len(packet) > TunMTU {
		panic(fmt.Sprintf("dataframe: inner packet %d > TunMTU %d", len(packet), TunMTU))
	}
	f.VNI = vni
	copy(f.SrcSID[:], srcSessionID[:3])
	copy(f.DstSID[:], dstSessionID[:3])

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
	dstMAC := MACFor(vni, dstSessionID)
	srcMAC := MACFor(vni, srcSessionID)
	copy(f.buf[VxlanHeaderSize:], dstMAC[:])
	copy(f.buf[VxlanHeaderSize+6:], srcMAC[:])
	binary.BigEndian.PutUint16(f.buf[VxlanHeaderSize+12:], innerEthType)

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

	// Inner Ethernet: recover SessionID prefixes from dst/src MACs (bytes 3-5).
	copy(f.DstSID[:], f.buf[VxlanHeaderSize+3:VxlanHeaderSize+6])
	copy(f.SrcSID[:], f.buf[VxlanHeaderSize+6+3:VxlanHeaderSize+6+6])

	payloadOffset := VxlanHeaderSize + EthHeaderSize
	f.Packet = f.buf[payloadOffset:f.Size]
	return nil
}

// Reset clears the frame for reuse.
func (f *DataFrame) Reset() {
	f.Packet = nil
	f.Size = 0
	f.SrcSID = [3]byte{}
	f.DstSID = [3]byte{}
}
