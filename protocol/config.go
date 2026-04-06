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
//	[clientPrivateKey:32][serverPublicKey:32][prefixAddr:16][prefixBits:1] = 81 bytes
type SessionConfig struct {
	ClientPrivateKey PrivateKey   // WG private key assigned to client
	ServerPublicKey  PublicKey    // Server's WG public key
	IPPrefix         netip.Prefix // Client's assigned IP prefix (e.g. 10.0.0.2/24)
}

const sessionConfigSize = 32 + 32 + 16 + 1 // 81

func (c *SessionConfig) Marshal() []byte {
	buf := make([]byte, sessionConfigSize)
	copy(buf[0:32], c.ClientPrivateKey[:])
	copy(buf[32:64], c.ServerPublicKey[:])

	addr := c.IPPrefix.Addr().As16()
	copy(buf[64:80], addr[:])
	buf[80] = byte(c.IPPrefix.Bits())
	return buf
}

func (c *SessionConfig) Unmarshal(data []byte) error {
	if len(data) < sessionConfigSize {
		return fmt.Errorf("session config too short: %d bytes", len(data))
	}
	copy(c.ClientPrivateKey[:], data[0:32])
	copy(c.ServerPublicKey[:], data[32:64])

	var addr16 [16]byte
	copy(addr16[:], data[64:80])
	bits := int(data[80])

	// Detect IPv4 vs IPv6 by checking if it's an IPv4-mapped IPv6
	addr := netip.AddrFrom16(addr16)
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	c.IPPrefix = netip.PrefixFrom(addr, bits)
	return nil
}

// MarshalSessionConfig is a convenience for ServerResponse.Config encoding.
func MarshalSessionConfig(clientPriv PrivateKey, serverPub PublicKey, prefix netip.Prefix) []byte {
	cfg := &SessionConfig{
		ClientPrivateKey: clientPriv,
		ServerPublicKey:  serverPub,
		IPPrefix:         prefix,
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
