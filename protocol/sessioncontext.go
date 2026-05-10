package protocol

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
)

type VNI_Ty uint32 // 24-bit virtual network identifier (VNI), stored in a uint32 for convenience

// String renders a VNI as both decimal and hex, e.g. "1234 (0x04d2)".
func (vni VNI_Ty) String() string {
	return fmt.Sprintf("%d (0x%06x)", uint32(vni), uint32(vni))
}

type CID_Ty [8]byte // 8 bytes (64 bits) of client ID, big-endian uint64

// the canonical log-format for a CID: "<decimal> (0x<hex>)".
func (cid CID_Ty) String() string {
	n := binary.BigEndian.Uint64(cid[:])
	return fmt.Sprintf("%d (0x%x)", n, n)
}

type SessionID_Ty [16]byte

type SessionContext struct {
	mu sync.RWMutex

	CID          CID_Ty       // 16 hex chars of the client ID
	VNI          VNI_Ty       // 24-bit virtual network identifier
	SessionID    SessionID_Ty // Session ID assigned by server
	SessionIndex uint32       // Unique session index for this session, used in packet headers
	IP           netip.Addr   // Client's assigned IP (e.g. 10.0.0.2)
	IPRanges     netip.Prefix // Internal network ranges routable via VPN (e.g. 10.0.0.0/24)
}

// PresetSessionConfig is the (vni, cid) pair the client knows up-front
// (from its CLI / config) and ships in ClientHello. Everything else on
// SessionContext is filled in by the server during the handshake.
type PresetSessionConfig struct {
	CID CID_Ty
	VNI VNI_Ty
}

func NewPresetSessionConfig(cid CID_Ty, vni VNI_Ty) PresetSessionConfig {
	return PresetSessionConfig{CID: cid, VNI: vni}
}
