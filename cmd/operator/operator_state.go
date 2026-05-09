package operator

import (
	"context"
	"errors"
	"net/netip"
	"sync"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
)

// operatorState owns every VNI's L2 plane and the shared underlay
// socket multiplexer. vniEntry rows are created lazily on the first
// reference (a client connecting, a peer being seeded, …).
//
// peerSeeds is the union of every underlay endpoint registered via
// SeedAllPeers — applied to vxlan.Port at vniEntry creation time so a
// peer registered before its first VNI is created still propagates
// to the resulting Port.
type operatorState struct {
	ctx context.Context

	mu    sync.RWMutex
	vnets map[protocol.VNI_Ty]*vniEntry
	Peers *PeerOperatorTable
}

func newOperatorState(ctx context.Context) *operatorState {
	return &operatorState{
		ctx:       ctx,
		vnets:     make(map[protocol.VNI_Ty]*vniEntry),
		Peers:     NewPeerOperatorTable(),
		peerSeeds: make(map[netip.AddrPort]struct{}),
	}
}

func (s *operatorState) snapshotSeeds() []netip.AddrPort {
	s.seedMu.Lock()
	defer s.seedMu.Unlock()
	out := make([]netip.AddrPort, 0, len(s.peerSeeds))
	for a := range s.peerSeeds {
		out = append(out, a)
	}
	return out
}

// GetOrCreateVNet returns the vniEntry for vni, creating it on first
// use. seeds is the static peer-underlay list applied at attach time
// (later additions go through (*vniEntry).vxlanPort.AddSeed via
// SeedAllPeers).
func (s *operatorState) GetVNet(vni common.VNI, seeds []netip.AddrPort) (*vniEntry, error) {
	s.mu.RLock()
	if vn, ok := s.vnets[vni]; ok {
		s.mu.RUnlock()
		return vn, nil
	}
	s.mu.RUnlock()
	return nil, errors.New("operator: VNI not found")
}

func (s *operatorState) CreateVNet(vni common.VNI, seeds []netip.AddrPort) (*vniEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if vn, ok := s.vnets[vni]; ok {
		return vn, nil
	}

	// Operator's vtep is a forwarder, not an endpoint — selfMAC and
	// selfIP stay zero so no frame is ever absorbed locally.
	v := vtep.New(s.ctx, common.VMAC{}, netip.Addr{})

	// Combine caller-supplied seeds with the operator-wide peer roster
	// so peers registered before this VNI was created propagate.
	allSeeds := append([]netip.AddrPort(nil), s.snapshotSeeds()...)
	allSeeds = append(allSeeds, seeds...)

	var port *vxlan.Port
	if s.vxlanDev != nil {
		var err error
		port, err = s.vxlanDev.Attach(vxlan.VNI(vni.Bytes3()), v, allSeeds)
		if err != nil {
			v.Close()
			return nil, err
		}
	}
	vn := &vniEntry{
		vtep:      v,
		vxlanPort: port,
		clients:   make(map[common.VMAC]*PeerClient),
	}
	s.vnets[vni] = vn
	return vn, nil
}

// AddClient attaches port to the per-VNI vtep and records cp in the
// VNI's client map. Returns the vniEntry for downstream use (e.g. so
// the read loop can call vn.vtep.DeliverL2 directly).
func (s *operatorState) AddClient(cp *PeerClient, port vtep.Port) (*vniEntry, error) {
	if cp == nil {
		return nil, errors.New("operator: nil ClientPeer")
	}
	vn, err := s.GetVNet(cp.VNI, nil)
	if err != nil {
		return nil, err
	}
	if err := vn.vtep.AttachPort(port); err != nil {
		return nil, err
	}
	vn.mu.Lock()
	vn.clients[cp.VMAC] = cp
	vn.mu.Unlock()
	return vn, nil
}

// RemoveClient detaches portID from the VNI's vtep and removes cp from
// the client map. No-op if the VNI is not registered.
func (s *operatorState) RemoveClient(cp *PeerClient, portID string) {
	s.mu.RLock()
	vn, ok := s.vnets[cp.VNI]
	s.mu.RUnlock()
	if !ok {
		return
	}
	vn.vtep.DetachPort(portID)
	vn.mu.Lock()
	if cur := vn.clients[cp.VMAC]; cur == cp {
		delete(vn.clients, cp.VMAC)
	}
	vn.mu.Unlock()
}

// Snapshot returns every connected client across every VNI. Used by
// the idle reaper.
func (s *operatorState) Snapshot() []*PeerClient {
	s.mu.RLock()
	vnets := make([]*vniEntry, 0, len(s.vnets))
	for _, vn := range s.vnets {
		vnets = append(vnets, vn)
	}
	s.mu.RUnlock()

	var out []*PeerClient
	for _, vn := range vnets {
		out = append(out, vn.Clients()...)
	}
	return out
}

// TotalClients counts clients across every VNI.
func (s *operatorState) TotalClients() int {
	s.mu.RLock()
	vnets := make([]*vniEntry, 0, len(s.vnets))
	for _, vn := range s.vnets {
		vnets = append(vnets, vn)
	}
	s.mu.RUnlock()

	n := 0
	for _, vn := range vnets {
		vn.mu.RLock()
		n += len(vn.clients)
		vn.mu.RUnlock()
	}
	return n
}

// CloseAll closes every client conn and tears down every vniEntry.
// The shared vxlanDev is owned by the Operator, not by the state, so
// it's not closed here.
func (s *operatorState) CloseAll() {
	for _, cp := range s.Snapshot() {
		_ = cp.Conn.Close()
	}
	s.mu.Lock()
	vnets := s.vnets
	s.vnets = make(map[common.VNI]*vniEntry)
	s.mu.Unlock()
	for _, vn := range vnets {
		vn.vtep.Close()
	}
}
