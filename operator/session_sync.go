package operator

import (
	"fmt"
	"net/netip"

	log "github.com/sirupsen/logrus"
)

// SessionSync wire format:
//   [sessionID:16][vnetID:16][operatorUUID:16][ipAddr:4][prefixBits:1]
// Total: 53 bytes per entry
//
// SessionRevoke wire format:
//   [sessionID:16][vnetID:16]
// Total: 32 bytes

const sessionSyncSize = 16 + 16 + 16 + 4 + 1 // 53

func encodeSessionSync(sessionID SessionIDType, vnetID VNetIDType, opUUID OperatorUUIDType, ip netip.Addr) []byte {
	buf := make([]byte, sessionSyncSize)
	copy(buf[0:16], sessionID[:])
	copy(buf[16:32], vnetID[:])
	copy(buf[32:48], opUUID[:])
	ip4 := ip.As4()
	copy(buf[48:52], ip4[:])
	buf[52] = 32 // /32
	return buf
}

func decodeSessionSync(data []byte) (sessionID SessionIDType, vnetID VNetIDType, opUUID OperatorUUIDType, ip netip.Addr, err error) {
	if len(data) < sessionSyncSize {
		err = fmt.Errorf("session sync too short: %d", len(data))
		return
	}
	copy(sessionID[:], data[0:16])
	copy(vnetID[:], data[16:32])
	copy(opUUID[:], data[32:48])
	var ip4 [4]byte
	copy(ip4[:], data[48:52])
	ip = netip.AddrFrom4(ip4)
	return
}

const sessionRevokeSize = 16 + 16 // 32

func encodeSessionRevoke(sessionID SessionIDType, vnetID VNetIDType) []byte {
	buf := make([]byte, sessionRevokeSize)
	copy(buf[0:16], sessionID[:])
	copy(buf[16:32], vnetID[:])
	return buf
}

func decodeSessionRevoke(data []byte) (sessionID SessionIDType, vnetID VNetIDType, err error) {
	if len(data) < sessionRevokeSize {
		err = fmt.Errorf("session revoke too short: %d", len(data))
		return
	}
	copy(sessionID[:], data[0:16])
	copy(vnetID[:], data[16:32])
	return
}

// broadcastSessionSync notifies all peer operators about a new client session.
func (o *Operator) broadcastSessionSync(cp *ClientPeer) {
	payload := encodeSessionSync(cp.SessionID, cp.VNetID, OperatorUUIDType(o.cfg.UUID), cp.IP.Addr())

	o.operators.mu.RLock()
	peers := make([]*OperatorPeer, 0, len(o.operators.peers))
	for _, p := range o.operators.peers {
		peers = append(peers, p)
	}
	o.operators.mu.RUnlock()

	for _, peer := range peers {
		if err := peer.SendControl(CtrlSessionSync, payload); err != nil {
			log.Errorf("SessionSync to %x: %v", peer.UUID, err)
		}
	}
}

// broadcastSessionRevoke notifies all peer operators that a client disconnected.
func (o *Operator) broadcastSessionRevoke(cp *ClientPeer) {
	payload := encodeSessionRevoke(cp.SessionID, cp.VNetID)

	o.operators.mu.RLock()
	peers := make([]*OperatorPeer, 0, len(o.operators.peers))
	for _, p := range o.operators.peers {
		peers = append(peers, p)
	}
	o.operators.mu.RUnlock()

	for _, peer := range peers {
		if err := peer.SendControl(CtrlSessionRevoke, payload); err != nil {
			log.Errorf("SessionRevoke to %x: %v", peer.UUID, err)
		}
	}
}

// handleSessionSync processes a SessionSync from a peer operator.
func (o *Operator) handleSessionSync(pools *VNetPoolMap, payload []byte) {
	sessionID, vnetID, opUUID, ip, err := decodeSessionSync(payload)
	if err != nil {
		log.Debugf("Bad session sync: %v", err)
		return
	}

	// Register in Registry so we can route to this client
	vnet := o.Registry.GetOrCreateVNet(vnetID)
	vnet.AddSession(sessionID, &SessionEntry{
		OperatorID: opUUID,
		IP:         ip,
		AllowedIPs: nil,
	})

	// Reserve the IP in our local pool to avoid allocation conflicts
	if pool, ok := pools.Get(vnetID); ok {
		pool.ReserveIP(ip)
	}

	log.Infof("SessionSync: %x on operator %x at %s (vnet %x)", sessionID, opUUID, ip, vnetID)
}

// handleSessionRevoke processes a SessionRevoke from a peer operator.
func (o *Operator) handleSessionRevoke(pools *VNetPoolMap, payload []byte) {
	sessionID, vnetID, err := decodeSessionRevoke(payload)
	if err != nil {
		log.Debugf("Bad session revoke: %v", err)
		return
	}

	// Get the IP before removing so we can unreserve it
	if vnet, ok := o.Registry.GetVNet(vnetID); ok {
		if entry, ok := vnet.GetSession(sessionID); ok {
			if pool, poolOK := pools.Get(vnetID); poolOK {
				pool.UnreserveIP(entry.IP)
			}
		}
		vnet.RemoveSession(sessionID)
	}

	log.Infof("SessionRevoke: %x (vnet %x)", sessionID, vnetID)
}

// forwardToRemoteOperator looks up the destination IP in the Registry
// and forwards the packet via the correct OperatorPeer.
func (o *Operator) forwardToRemoteOperator(srcPeer *ClientPeer, dstAddr netip.Addr, data []byte) bool {
	// Search all VNets for a session matching this IP
	vnet, ok := o.Registry.GetVNet(srcPeer.VNetID)
	if !ok {
		return false
	}

	vnet.mu.RLock()
	var targetOpUUID OperatorUUIDType
	found := false
	for _, entry := range vnet.Sessions {
		if entry.IP == dstAddr {
			targetOpUUID = entry.OperatorID
			found = true
			break
		}
	}
	vnet.mu.RUnlock()

	if !found {
		return false
	}

	// Skip if the target is on this operator (shouldn't happen, local lookup already failed)
	if targetOpUUID == OperatorUUIDType(o.cfg.UUID) {
		return false
	}

	peer, ok := o.operators.Get(targetOpUUID)
	if !ok {
		log.Debugf("Operator %x not connected for forwarding", targetOpUUID)
		return false
	}

	if err := peer.SendData([16]byte(srcPeer.VNetID), data); err != nil {
		log.Errorf("Forward to operator %x: %v", targetOpUUID, err)
		return false
	}
	return true
}
