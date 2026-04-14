package vxlan

import (
	"fmt"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/jabberwocky238/gasoline/common"
)

// Plane is the operator-side VXLAN data plane.
//
// It owns one UDP socket for inter-operator traffic, a MACTable for L2
// forwarding, and provides two top-level entry points:
//
//	Forward(vni, frame)  — called by local sources (TAP devices, client
//	                        conn read loops) to inject an inbound L2 frame
//	                        for routing.
//	RxLoop()             — reads VXLAN-encapsulated UDP datagrams, learns
//	                        the source MAC, then re-enters Forward with
//	                        the decapsulated inner frame.
type Plane struct {
	udp   *net.UDPConn
	table *MACTable

	mu     sync.Mutex
	closed bool
	done   chan struct{}
}

// New constructs a Plane bound to the given UDP socket. The Plane does not
// start any goroutines until Start.
func New(udp *net.UDPConn) *Plane {
	return &Plane{
		udp:   udp,
		table: NewMACTable(),
		done:  make(chan struct{}),
	}
}

// Table exposes the MACTable for direct registration / inspection.
func (p *Plane) Table() *MACTable { return p.table }

// Start spawns the RxLoop goroutine.
func (p *Plane) Start() {
	go p.RxLoop()
}

// Close stops the RxLoop and closes the UDP socket.
func (p *Plane) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	close(p.done)
	if p.udp != nil {
		return p.udp.Close()
	}
	return nil
}

// RegisterPort attaches a local Port at (vni, mac).
func (p *Plane) RegisterPort(vni common.VNI, mac common.VMAC, port Port) {
	p.table.RegisterLocal(vni, mac, port)
}

// UnregisterPort removes a local Port binding.
func (p *Plane) UnregisterPort(vni common.VNI, mac common.VMAC) {
	p.table.UnregisterLocal(vni, mac)
}

// Forward routes an Ethernet frame in the given VNI.
//
// Decision tree:
//
//	dstMAC == FF:FF:FF:FF:FF:FF  → Flood
//	dstMAC ∈ local table         → port.SendFrame(frame)
//	dstMAC ∈ remote table        → VXLAN-wrap and UDP-send
//	otherwise                    → drop (unknown unicast)
//
// Inner payload is never inspected.
func (p *Plane) Forward(vni common.VNI, frame []byte) error {
	if len(frame) < common.EthHeaderSize {
		return fmt.Errorf("vxlan: frame too short %d", len(frame))
	}
	var dst, src common.VMAC
	copy(dst[:], frame[0:6])
	copy(src[:], frame[6:12])

	// Source learning is the caller's responsibility for local injection
	// (we'd register the source automatically here, but RegisterPort is the
	// authoritative path for local ports — we don't want to overwrite it).
	// Remote source learning is done in RxLoop.

	if dst == common.EthBroadcastMAC {
		p.Flood(vni, frame, src)
		return nil
	}

	if port, addr, found := p.table.Lookup(vni, dst); found {
		if port != nil {
			return port.SendFrame(frame)
		}
		return p.sendVXLAN(vni, frame, addr)
	}

	// Unknown unicast: drop. Real switches would flood; for our zero-trust
	// L2 we prefer drop + log to surface ARP/learning bugs.
	log.Debugf("vxlan: unknown dst vni=%s mac=%x dropping", vni, dst)
	return nil
}

// Flood replicates a frame to all local ports and all known remote
// operators in the same VNI, skipping the source if provided.
func (p *Plane) Flood(vni common.VNI, frame []byte, skipSrc common.VMAC) {
	for mac, port := range p.table.LocalsInVNI(vni) {
		if mac == skipSrc {
			continue
		}
		_ = port.SendFrame(frame)
	}
	// Avoid duplicate sends to the same operator endpoint by deduping addresses.
	seen := make(map[string]struct{})
	for mac, addr := range p.table.RemotesInVNI(vni) {
		if mac == skipSrc {
			continue
		}
		key := addr.String()
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		_ = p.sendVXLAN(vni, frame, addr)
	}
}

// sendVXLAN prepends the VXLAN header and writes one UDP datagram.
func (p *Plane) sendVXLAN(vni common.VNI, frame []byte, addr *net.UDPAddr) error {
	if p.udp == nil || addr == nil {
		return nil
	}
	df := common.GetFrame()
	wire := df.EncodeFrame(vni, frame)
	_, err := p.udp.WriteToUDP(wire, addr)
	common.PutFrame(df)
	return err
}

// RxLoop reads VXLAN datagrams from the UDP socket, learns the inner
// source MAC, then dispatches via Forward.
func (p *Plane) RxLoop() {
	readBuf := make([]byte, common.MaxVxlanPayload)
	for {
		select {
		case <-p.done:
			return
		default:
		}

		n, srcAddr, err := p.udp.ReadFromUDP(readBuf)
		if err != nil {
			return
		}

		df := common.GetFrame()
		if err := df.Decode(readBuf[:n]); err != nil {
			common.PutFrame(df)
			continue
		}

		// Learn (vni, srcMAC) → srcAddr from every frame we receive.
		p.table.LearnRemote(df.VNI, df.SrcMAC, srcAddr)

		// Dispatch the inner Ethernet frame through the local plane.
		_ = p.Forward(df.VNI, df.Frame())
		common.PutFrame(df)
	}
}
