package protocol

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/blake2s"
)

// cidDomain domain-separates the CID derivation from any other BLAKE2s use.
var cidDomain = []byte("gaso")

// DeriveCID computes a client's CID from its static public key:
//
//	CID = BLAKE2s-256("gaso" || pubkey)[0:8]
//
// The CID is therefore a function of identity, not a client-chosen value —
// this is what makes CID spoofing impossible (PRD §3.1). The server recomputes
// it from the pubkey recovered during the Noise handshake and rejects any
// mismatch.
func DeriveCID(pubkey [32]byte) CID_Ty {
	h, _ := blake2s.New256(nil)
	h.Write(cidDomain)
	h.Write(pubkey[:])
	sum := h.Sum(nil)
	var cid CID_Ty
	copy(cid[:], sum[:8])
	return cid
}

// ParseCID accepts a CID written as either a decimal uint64 (default)
// or a hex string prefixed with "0x"/"0X". Both forms are big-endian
// 8 bytes; values shorter than 8 bytes are zero-padded on the left
// (most-significant side). Returns an error on overflow or bad input.
func ParseCID(s string) (CID_Ty, error) {
	var cid CID_Ty
	s = strings.TrimSpace(s)
	if s == "" {
		return cid, fmt.Errorf("cid: empty")
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		body := s[2:]
		if len(body)%2 == 1 {
			body = "0" + body
		}
		b, err := hex.DecodeString(body)
		if err != nil {
			return cid, fmt.Errorf("cid %q: invalid hex: %v", s, err)
		}
		if len(b) > len(cid) {
			return cid, fmt.Errorf("cid %q: too many bytes (%d > %d)", s, len(b), len(cid))
		}
		copy(cid[len(cid)-len(b):], b)
		return cid, nil
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return cid, fmt.Errorf("cid %q: %v", s, err)
	}
	binary.BigEndian.PutUint64(cid[:], n)
	return cid, nil
}

// FormatCID renders a CID as its big-endian uint64 decimal string.
// This is the inverse of ParseCID for the default (decimal) form.
func (cid CID_Ty) FormatCID() string {
	return strconv.FormatUint(binary.BigEndian.Uint64(cid[:]), 10)
}
