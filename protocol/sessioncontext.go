package protocol

import (
	"net/netip"
	"sync"
)

type VNI_Ty uint32
type CID_Ty [8]byte
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
