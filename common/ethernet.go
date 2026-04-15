package common

import "encoding/binary"

// --------------- Public API ---------------

// WrapEth borrows a DataFrame from the global pool and stamps an
// Ethernet-only frame (no VXLAN header) into its backing buffer. Returns
// the *DataFrame; caller obtains the wire bytes via df.Bytes() and MUST
// release it via PutFrame after the bytes have been consumed.
//
// Replaces the old `make([]byte, ...) + 2 × copy` pattern with a single
// pool-borrow + the unavoidable header/payload copies. The returned
// df.size sets up Bytes()/Frame()/EtherType() / etc to read the eth
// header at offset 0 (note: VxlanHeaderSize-shifted accessors like
// DstMAC/SrcMAC/EtherType assume a VXLAN prefix and will be wrong here
// — use ParseEth on df.Bytes() if you need to introspect).
func WrapEth(dstMAC, srcMAC VMAC, ethType uint16, payload []byte) *DataFrame {
	df := GetFrame()
	WriteEthHeader(df.buf[:], dstMAC, srcMAC, ethType)
	copy(df.buf[EthHeaderSize:], payload)
	df.size = EthHeaderSize + len(payload)
	return df
}

// WriteEthHeader stamps an Ethernet header at dst[0:14].
// dst must have at least EthHeaderSize bytes of capacity.
// Used by DataFrame.Encode and by WrapEth.
func WriteEthHeader(dst []byte, dstMAC, srcMAC VMAC, ethType uint16) {
	_ = dst[EthHeaderSize-1] // bounds hint
	copy(dst[0:6], dstMAC[:])
	copy(dst[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(dst[12:14], ethType)
}

// ParseEth returns (dstMAC, srcMAC, ethType, payload) of an Ethernet frame.
// The returned payload slice aliases into frame — do not mutate.
func ParseEth(frame []byte) (dstMAC, srcMAC VMAC, ethType uint16, payload []byte, ok bool) {
	if len(frame) < EthHeaderSize {
		return
	}
	dstMAC = VMAC(frame[0:6])
	srcMAC = VMAC(frame[6:12])
	ethType = binary.BigEndian.Uint16(frame[12:14])
	payload = frame[EthHeaderSize:]
	ok = true
	return
}

// --------------- Keepalive ---------------

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
	if !parsed || ethType != EtherTypeKeepalive || dst != KeepaliveZeroMAC {
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

// BuildKeepaliveRequest constructs a client→operator keepalive frame
// inside a pooled DataFrame. Caller releases via PutFrame.
func BuildKeepaliveRequest(selfMAC VMAC) *DataFrame {
	return WrapEth(KeepaliveZeroMAC, selfMAC, EtherTypeKeepalive, nil)
}

// BuildKeepaliveReply constructs an operator→client keepalive reply frame
// inside a pooled DataFrame. Caller releases via PutFrame.
func BuildKeepaliveReply(clientMAC VMAC) *DataFrame {
	return WrapEth(clientMAC, KeepaliveZeroMAC, EtherTypeKeepalive, nil)
}
