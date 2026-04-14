package common

import (
	"bytes"
	"testing"
)

func TestDataFrameVXLANEncodeDecode(t *testing.T) {
	vni := VNI(0xAABBCC)
	srcSID := [16]byte{0x11, 0x22, 0x33, 0xFF}
	dstSID := [16]byte{0x44, 0x55, 0x66, 0xEE}
	packet := []byte{
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x01, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x02,
		0x0a, 0x00, 0x00, 0x03,
		0x00, 0x50, 0x00, 0x51,
		0x00, 0x08, 0x00, 0x00,
	}

	src := &DataFrame{}
	wire := src.Encode(vni, srcSID, dstSID, packet)

	if len(wire) != VxlanHeaderSize+EthHeaderSize+len(packet) {
		t.Fatalf("wire length = %d, want %d", len(wire), VxlanHeaderSize+EthHeaderSize+len(packet))
	}

	if wire[0]&vxlanFlagsValid == 0 {
		t.Errorf("VXLAN I flag not set: byte 0 = 0x%02x", wire[0])
	}

	if wire[4] != 0xAA || wire[5] != 0xBB || wire[6] != 0xCC {
		t.Errorf("VNI mismatch: got %02x%02x%02x, want AABBCC", wire[4], wire[5], wire[6])
	}

	// Dst MAC: (VNI[0] & 0xFE | 0x02), VNI[1], VNI[2], dstSID[0..2]
	// 0xAA & 0xFE = 0xAA; 0xAA | 0x02 = 0xAA
	wantDstMAC := [6]byte{0xAA, 0xBB, 0xCC, 0x44, 0x55, 0x66}
	if !bytes.Equal(wire[VxlanHeaderSize:VxlanHeaderSize+6], wantDstMAC[:]) {
		t.Errorf("dst MAC mismatch:\n  got:  %x\n  want: %x",
			wire[VxlanHeaderSize:VxlanHeaderSize+6], wantDstMAC)
	}

	wantSrcMAC := [6]byte{0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33}
	if !bytes.Equal(wire[VxlanHeaderSize+6:VxlanHeaderSize+12], wantSrcMAC[:]) {
		t.Errorf("src MAC mismatch:\n  got:  %x\n  want: %x",
			wire[VxlanHeaderSize+6:VxlanHeaderSize+12], wantSrcMAC)
	}

	if wire[VxlanHeaderSize+12] != 0x08 || wire[VxlanHeaderSize+13] != 0x00 {
		t.Errorf("inner ethertype: got %02x%02x, want 0800",
			wire[VxlanHeaderSize+12], wire[VxlanHeaderSize+13])
	}

	dst := &DataFrame{}
	if err := dst.Decode(wire); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if !bytes.Equal(dst.Packet, packet) {
		t.Errorf("packet mismatch:\n  got:  %x\n  want: %x", dst.Packet, packet)
	}
	if dst.VNI != vni {
		t.Errorf("recovered VNI = %s, want %s", dst.VNI, vni)
	}
	if dst.SrcSID != [3]byte{0x11, 0x22, 0x33} {
		t.Errorf("recovered SrcSID = %x, want 112233", dst.SrcSID)
	}
	if dst.DstSID != [3]byte{0x44, 0x55, 0x66} {
		t.Errorf("recovered DstSID = %x, want 445566", dst.DstSID)
	}
}

func TestDataFrameMACUnicastBit(t *testing.T) {
	// VNI high byte 0x01 has unicast bit set; MACFor must clear it and set locally-admin bit.
	vni := VNI(0x010203)
	sid := [16]byte{0xAA, 0xBB, 0xCC}
	mac := MACFor(vni, sid)

	if mac[0]&0x01 != 0 {
		t.Errorf("MAC[0] should have unicast bit clear, got 0x%02x", mac[0])
	}
	if mac[0]&0x02 == 0 {
		t.Errorf("MAC[0] should have locally-administered bit set, got 0x%02x", mac[0])
	}
}

func TestDataFrameDecodeInvalidFlags(t *testing.T) {
	data := make([]byte, VxlanHeaderSize+EthHeaderSize+20)
	df := &DataFrame{}
	if err := df.Decode(data); err == nil {
		t.Error("expected error for missing I flag")
	}
}

func TestDataFrameDecodeTooShort(t *testing.T) {
	df := &DataFrame{}
	if err := df.Decode(make([]byte, 10)); err == nil {
		t.Error("expected error for short frame")
	}
}
