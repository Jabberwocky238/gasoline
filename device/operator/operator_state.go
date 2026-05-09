package operator

import (
	"context"
	"sync"

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
		ctx:   ctx,
		vnets: make(map[protocol.VNI_Ty]*vniEntry),
		Peers: NewPeerTable(),
	}
}
