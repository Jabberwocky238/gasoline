package config

import (
	"encoding/hex"
	"fmt"
	"strconv"
)

type VNI uint32

const VNIMax VNI = 0xFFFFFF

func (v VNI) Valid() bool {
	return v <= VNIMax
}

func (v VNI) String() string {
	return fmt.Sprintf("%06x", uint32(v))
}

func (v VNI) Bytes3() [3]byte {
	return [3]byte{byte(v >> 16), byte(v >> 8), byte(v)}
}

func VNIFromBytes3(b [3]byte) VNI {
	return VNI(uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]))
}

func ParseVNI(s string) (VNI, error) {
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		n, err := strconv.ParseUint(s[2:], 16, 32)
		if err != nil {
			return 0, err
		}
		if VNI(n) > VNIMax {
			return 0, fmt.Errorf("vni out of range: %s", s)
		}
		return VNI(n), nil
	}
	if n, err := strconv.ParseUint(s, 10, 32); err == nil {
		if VNI(n) > VNIMax {
			return 0, fmt.Errorf("vni out of range: %s", s)
		}
		return VNI(n), nil
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) > 3 {
		return 0, fmt.Errorf("invalid vni: %q", s)
	}
	var padded [3]byte
	copy(padded[3-len(b):], b)
	return VNIFromBytes3(padded), nil
}
