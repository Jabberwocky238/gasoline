package ctrl

import (
	"context"
	"net/netip"

	"github.com/jabberwocky238/gasoline/common"
)

// server implements OperatorServiceServer. Lives entirely within ctrl.
type server struct {
	UnimplementedOperatorServiceServer
	cp *ControlPlane
}

func (s *server) Register(ctx context.Context, req *RegisterReq) (*RegisterResp, error) {
	var remoteUUID [16]byte
	copy(remoteUUID[:], req.Uuid)

	s.cp.Registry.SetOperator(remoteUUID, &OperatorInfo{Addr: req.ExternalAddr})
	s.cp.log.Infof("Operator %x registered, external %s", remoteUUID, req.ExternalAddr)

	// Dial back so we have a gRPC client to the caller
	if _, ok := s.cp.Peers.Get(remoteUUID); !ok && req.ExternalAddr != "" {
		go func() {
			if err := s.cp.dialBack(req.ExternalAddr, remoteUUID); err != nil {
				s.cp.log.Errorf("Dial-back to %x at %s: %v", remoteUUID, req.ExternalAddr, err)
			}
		}()
	}

	return &RegisterResp{
		Uuid:         s.cp.uuid[:],
		ExternalAddr: s.cp.cfg.ExternalAddr,
	}, nil
}

func (s *server) Ping(ctx context.Context, req *PingReq) (*PingResp, error) {
	return &PingResp{UnixNano: req.UnixNano}, nil
}

func (s *server) Discover(ctx context.Context, req *DiscoverReq) (*DiscoverResp, error) {
	entries := []*OperatorEntry{
		{Uuid: s.cp.uuid[:], Addr: s.cp.cfg.ExternalAddr},
	}
	for uuid, info := range s.cp.Registry.AllOperators() {
		u := uuid
		entries = append(entries, &OperatorEntry{Uuid: u[:], Addr: info.Addr})
	}
	return &DiscoverResp{Operators: entries}, nil
}

func (s *server) NotifySession(ctx context.Context, req *SessionEvent) (*Ack, error) {
	switch e := req.Event.(type) {
	case *SessionEvent_Sync:
		s.handleSync(e.Sync)
	case *SessionEvent_Revoke:
		s.handleRevoke(e.Revoke)
	}
	return &Ack{}, nil
}

func (s *server) handleSync(msg *SessionSync) {
	var sessionID, opUUID [16]byte
	copy(sessionID[:], msg.SessionId)
	copy(opUUID[:], msg.OperatorUuid)
	vni := vniFromBytes(msg.Vni)

	var cid common.VMAC
	if len(msg.Cid) == common.VMACLen {
		copy(cid[:], msg.Cid)
	}

	var ip netip.Addr
	if len(msg.IpAddr) == 4 {
		ip = netip.AddrFrom4([4]byte(msg.IpAddr))
	} else if len(msg.IpAddr) == 16 {
		ip = netip.AddrFrom16([16]byte(msg.IpAddr))
	} else {
		return
	}

	vnet := s.cp.Registry.GetOrCreateVNet(vni)
	vnet.Add(sessionID, &SessionInfo{OperatorUUID: opUUID, VMAC:        cid, IP: ip})
	s.cp.log.Infof("SessionSync: %x cid=%x on operator %x at %s (vni %s)", sessionID, cid, opUUID, ip, vni)

	if s.cp.cfg.OnSessionSync != nil {
		s.cp.cfg.OnSessionSync(vni, opUUID, cid, ip)
	}
}

func (s *server) handleRevoke(msg *SessionRevoke) {
	var sessionID [16]byte
	copy(sessionID[:], msg.SessionId)
	vni := vniFromBytes(msg.Vni)

	var revokedIP netip.Addr
	var revokedCID common.VMAC
	var revokedOp [16]byte
	if vnet, ok := s.cp.Registry.GetVNet(vni); ok {
		if info, ok := vnet.Get(sessionID); ok {
			revokedIP = info.IP
			revokedCID = info.VMAC
			revokedOp = info.OperatorUUID
		}
		vnet.Remove(sessionID)
	}
	s.cp.log.Infof("SessionRevoke: %x (vni %s)", sessionID, vni)

	if s.cp.cfg.OnSessionRevoke != nil && revokedIP.IsValid() {
		s.cp.cfg.OnSessionRevoke(vni, revokedOp, sessionID, revokedCID, revokedIP)
	}
}
