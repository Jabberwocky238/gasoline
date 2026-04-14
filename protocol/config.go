package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol/encryption"
)

// SessionConfig is the config the server sends to the client after successful auth.
//
// Wire format (fixed part = 101 bytes):
//
//	[sessionID:16][vni:4][clientPrivateKey:32][serverPublicKey:32]
//	[prefixAddr:16][prefixBits:1][rangeCount:2][ranges...]
type SessionConfig struct {
	SessionID        [16]byte              // Session ID assigned by server
	VNI              common.VNI            // 24-bit virtual network identifier
	ClientPrivateKey encryption.PrivateKey // WG private key assigned to client
	ServerPublicKey  encryption.PublicKey  // Server's WG public key
	IPPrefix         netip.Prefix          // Client's assigned IP (e.g. 10.0.0.2/24)
	AllowedRanges    []netip.Prefix        // Internal network ranges routable via VPN
}

const (
	configFixedSize = 16 + 4 + 32 + 32 + 16 + 1 // 101
	prefixEntrySize = 16 + 1                    // 17 per prefix
)

func (c *SessionConfig) Marshal() []byte {
	rangeCount := len(c.AllowedRanges)
	totalSize := configFixedSize + 2 + rangeCount*prefixEntrySize
	buf := make([]byte, totalSize)

	// SessionID + VNI
	copy(buf[0:16], c.SessionID[:])
	binary.BigEndian.PutUint32(buf[16:20], uint32(c.VNI))

	// Keys
	copy(buf[20:52], c.ClientPrivateKey[:])
	copy(buf[52:84], c.ServerPublicKey[:])

	// Client IP prefix (always stored as 16-byte addr)
	addr16 := c.IPPrefix.Addr().As16()
	copy(buf[84:100], addr16[:])
	buf[100] = byte(c.IPPrefix.Bits())

	// Allowed ranges
	binary.BigEndian.PutUint16(buf[101:103], uint16(rangeCount))
	offset := 103
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

	// SessionID + VNI
	copy(c.SessionID[:], data[0:16])
	c.VNI = common.VNI(binary.BigEndian.Uint32(data[16:20]))

	// Keys
	copy(c.ClientPrivateKey[:], data[20:52])
	copy(c.ServerPublicKey[:], data[52:84])

	// Client IP prefix
	var a16 [16]byte
	copy(a16[:], data[84:100])
	bits := int(data[100])
	addr := netip.AddrFrom16(a16)
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	c.IPPrefix = netip.PrefixFrom(addr, bits)

	// Allowed ranges
	rangeCount := int(binary.BigEndian.Uint16(data[101:103]))
	expectedLen := configFixedSize + 2 + rangeCount*prefixEntrySize
	if len(data) < expectedLen {
		return fmt.Errorf("session config too short for %d ranges: need %d, got %d",
			rangeCount, expectedLen, len(data))
	}

	c.AllowedRanges = make([]netip.Prefix, rangeCount)
	offset := 103
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
func MarshalSessionConfig(clientPriv encryption.PrivateKey, serverPub encryption.PublicKey, prefix netip.Prefix, allowedRanges []netip.Prefix) []byte {
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
