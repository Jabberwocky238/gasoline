package common

import (
	"bytes"
	"testing"
)

func TestDataFrameVXLANEncodeDecode(t *testing.T) {
	vni := VNI(0xAABBCC)
	srcCID := ClientID{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	dstCID := ClientID{0x02, 0x66, 0x77, 0x88, 0x99, 0xAA}
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
	wire := src.Encode(vni, srcCID, dstCID, packet)

	if len(wire) != VxlanHeaderSize+EthHeaderSize+len(packet) {
		t.Fatalf("wire length = %d, want %d", len(wire), VxlanHeaderSize+EthHeaderSize+len(packet))
	}

	if wire[0]&vxlanFlagsValid == 0 {
		t.Errorf("VXLAN I flag not set: byte 0 = 0x%02x", wire[0])
	}

	if wire[4] != 0xAA || wire[5] != 0xBB || wire[6] != 0xCC {
		t.Errorf("VNI mismatch: got %02x%02x%02x, want AABBCC", wire[4], wire[5], wire[6])
	}

	// Dst MAC = dstCID verbatim
	if !bytes.Equal(wire[VxlanHeaderSize:VxlanHeaderSize+6], dstCID[:]) {
		t.Errorf("dst MAC mismatch:\n  got:  %x\n  want: %x",
			wire[VxlanHeaderSize:VxlanHeaderSize+6], dstCID)
	}
	// Src MAC = srcCID verbatim
	if !bytes.Equal(wire[VxlanHeaderSize+6:VxlanHeaderSize+12], srcCID[:]) {
		t.Errorf("src MAC mismatch:\n  got:  %x\n  want: %x",
			wire[VxlanHeaderSize+6:VxlanHeaderSize+12], srcCID)
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
	if dst.EtherType != EtherTypeIPv4 {
		t.Errorf("recovered EtherType = 0x%04x, want 0x0800", dst.EtherType)
	}
	if dst.SrcCID != srcCID {
		t.Errorf("recovered SrcCID = %x, want %x", dst.SrcCID, srcCID)
	}
	if dst.DstCID != dstCID {
		t.Errorf("recovered DstCID = %x, want %x", dst.DstCID, dstCID)
	}
}

func TestDataFrameVXLANIPv6(t *testing.T) {
	vni := VNI(0x123456)
	srcCID := ClientID{0x02, 0x01, 0x02, 0x03, 0x04, 0x05}
	dstCID := ClientID{0x02, 0x06, 0x07, 0x08, 0x09, 0x0A}
	packet := make([]byte, 40)
	packet[0] = 0x60 // IPv6 version nibble

	src := &DataFrame{}
	wire := src.Encode(vni, srcCID, dstCID, packet)

	if wire[VxlanHeaderSize+12] != 0x86 || wire[VxlanHeaderSize+13] != 0xDD {
		t.Errorf("inner ethertype: got %02x%02x, want 86DD",
			wire[VxlanHeaderSize+12], wire[VxlanHeaderSize+13])
	}

	dst := &DataFrame{}
	if err := dst.Decode(wire); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if dst.EtherType != EtherTypeIPv6 {
		t.Errorf("EtherType = 0x%04x, want 0x86DD", dst.EtherType)
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
