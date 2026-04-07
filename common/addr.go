package common

import (
	"encoding/binary"
	"net/netip"
)

// AddToAddr adds an offset to a netip.Addr (IPv4 only).
func AddToAddr(base netip.Addr, offset uint32) netip.Addr {
	b4 := base.As4()
	val := uint32(b4[0])<<24 | uint32(b4[1])<<16 | uint32(b4[2])<<8 | uint32(b4[3])
	val += offset
	return netip.AddrFrom4([4]byte{
		byte(val >> 24), byte(val >> 16), byte(val >> 8), byte(val),
	})
}

// EncodeVNetID encodes a decimal vnet number into a [16]byte.
func EncodeVNetID(num uint64) [16]byte {
	var id [16]byte
	binary.BigEndian.PutUint64(id[8:], num)
	return id
}
