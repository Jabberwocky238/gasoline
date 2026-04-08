package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
)

// SessionConfig is the config the server sends to the client after successful auth.
//
// Wire format:
//
//	[clientPrivateKey:32][serverPublicKey:32][prefixAddr:16][prefixBits:1]
//	[rangeCount:2][range0_addr:16][range0_bits:1]...[rangeN_addr:16][rangeN_bits:1]
//
// Fixed part = 81 bytes, each range = 17 bytes.
type SessionConfig struct {
	SessionID        [16]byte       // Session ID assigned by server
	VNetID           [16]byte       // Virtual network ID
	ClientPrivateKey PrivateKey     // WG private key assigned to client
	ServerPublicKey  PublicKey      // Server's WG public key
	IPPrefix         netip.Prefix   // Client's assigned IP (e.g. 10.0.0.2/24)
	AllowedRanges    []netip.Prefix // Internal network ranges routable via VPN
}

const (
	configFixedSize = 16 + 16 + 32 + 32 + 16 + 1 // 113
	prefixEntrySize = 16 + 1                 // 17 per prefix
)

func (c *SessionConfig) Marshal() []byte {
	rangeCount := len(c.AllowedRanges)
	totalSize := configFixedSize + 2 + rangeCount*prefixEntrySize
	buf := make([]byte, totalSize)

	// SessionID + VNetID
	copy(buf[0:16], c.SessionID[:])
	copy(buf[16:32], c.VNetID[:])

	// Keys
	copy(buf[32:64], c.ClientPrivateKey[:])
	copy(buf[64:96], c.ServerPublicKey[:])

	// Client IP prefix (always stored as 16-byte addr)
	addr16 := c.IPPrefix.Addr().As16()
	copy(buf[96:112], addr16[:])
	buf[112] = byte(c.IPPrefix.Bits())

	// Allowed ranges
	binary.BigEndian.PutUint16(buf[113:115], uint16(rangeCount))
	offset := 115
	for _, r := range c.AllowedRanges {
		a16 := r.Addr().As16()
		copy(buf[offset:offset+16], a16[:])
		buf[offset+16] = byte(r.Bits())
		offset += prefixEntrySize
	}

	return buf
}

func (c *SessionConfig) Unmarshal(data []byte) error {
	if len(data) < configFixedSize+2 {
		return fmt.Errorf("session config too short: %d bytes", len(data))
	}

	// SessionID + VNetID
	copy(c.SessionID[:], data[0:16])
	copy(c.VNetID[:], data[16:32])

	// Keys
	copy(c.ClientPrivateKey[:], data[32:64])
	copy(c.ServerPublicKey[:], data[64:96])

	// Client IP prefix
	var a16 [16]byte
	copy(a16[:], data[96:112])
	bits := int(data[112])
	addr := netip.AddrFrom16(a16)
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	c.IPPrefix = netip.PrefixFrom(addr, bits)

	// Allowed ranges
	rangeCount := int(binary.BigEndian.Uint16(data[113:115]))
	expectedLen := configFixedSize + 2 + rangeCount*prefixEntrySize
	if len(data) < expectedLen {
		return fmt.Errorf("session config too short for %d ranges: need %d, got %d",
			rangeCount, expectedLen, len(data))
	}

	c.AllowedRanges = make([]netip.Prefix, rangeCount)
	offset := 115
	for i := 0; i < rangeCount; i++ {
		var ra [16]byte
		copy(ra[:], data[offset:offset+16])
		rbits := int(data[offset+16])
		raddr := netip.AddrFrom16(ra)
		if raddr.Is4In6() {
			raddr = raddr.Unmap()
		}
		c.AllowedRanges[i] = netip.PrefixFrom(raddr, rbits)
		offset += prefixEntrySize
	}

	return nil
}

// MarshalSessionConfig is a convenience helper.
func MarshalSessionConfig(clientPriv PrivateKey, serverPub PublicKey, prefix netip.Prefix, allowedRanges []netip.Prefix) []byte {
	cfg := &SessionConfig{
		ClientPrivateKey: clientPriv,
		ServerPublicKey:  serverPub,
		IPPrefix:         prefix,
		AllowedRanges:    allowedRanges,
	}
	return cfg.Marshal()
}

// EncodePrefix writes a netip.Prefix as [addr:4or16][bits:1].
func EncodePrefix(w io.Writer, p netip.Prefix) error {
	addr := p.Addr()
	var addrBytes []byte
	if addr.Is4() {
		a4 := addr.As4()
		addrBytes = a4[:]
	} else {
		a16 := addr.As16()
		addrBytes = a16[:]
	}
	if _, err := w.Write(addrBytes); err != nil {
		return err
	}
	_, err := w.Write([]byte{byte(p.Bits())})
	return err
}

// DecodePrefix reads a netip.Prefix. isIPv6 selects 16-byte vs 4-byte address.
func DecodePrefix(r io.Reader, isIPv6 bool) (netip.Prefix, error) {
	size := 4
	if isIPv6 {
		size = 16
	}
	buf := make([]byte, size+1)
	if _, err := io.ReadFull(r, buf); err != nil {
		return netip.Prefix{}, err
	}
	var addr netip.Addr
	if isIPv6 {
		var a [16]byte
		copy(a[:], buf[:16])
		addr = netip.AddrFrom16(a)
	} else {
		var a [4]byte
		copy(a[:], buf[:4])
		addr = netip.AddrFrom4(a)
	}
	bits := int(buf[size])
	return netip.PrefixFrom(addr, bits), nil
}

// helper for length-prefixed config in ServerResponse
func EncodeLengthPrefixed(w io.Writer, data []byte) error {
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func DecodeLengthPrefixed(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return data, nil
}
