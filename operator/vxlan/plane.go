package vxlan

import (
	"fmt"
	"net"
	"net/netip"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/jabberwocky238/gasoline/common"
)

// Plane is the operator-side VXLAN data plane.
//
// Owns one *net.UDPConn for inter-operator traffic plus a MACTable for
// L2 forwarding. Two top-level entry points:
//
//	Forward(vni, frame) — local sources (TAP devices, client conn read
//	                       loops) inject inbound L2 frames here.
//	RxLoop()            — single goroutine: ReadFromUDPAddrPort → decode
//	                       → LearnRemote → Forward, all inline.
//
// Single-goroutine RX is intentional: per-client transport.WritePacket
// is serialised on the destination conn (AEAD nonce + sendto), so any
// fan-out on the operator side just adds scheduler churn without
// unblocking the downstream bottleneck.
type Plane struct {
	conn  *net.UDPConn
	table *MACTable

	mu     sync.Mutex
	closed bool
	done   chan struct{}
}

// New constructs a Plane bound to the given UDP socket. The Plane does
// not start any goroutines until Start. The Plane takes ownership of
// conn — Close will close it.
func New(conn *net.UDPConn) *Plane {
	return &Plane{
		conn:  conn,
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

// Close stops the RxLoop and closes the underlying socket.
func (p *Plane) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	close(p.done)
	if p.conn != nil {
		return p.conn.Close()
	}
	return nil
}

// RegisterPort attaches a local Port at (vni, mac).
func (p *Plane) RegisterPort(vni common.VNI, mac common.VMAC, lp Port) {
	p.table.RegisterLocal(vni, mac, lp)
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

	if dst == common.EthBroadcastMAC {
		p.Flood(vni, frame, src)
		return nil
	}

	if lp, addr, found := p.table.Lookup(vni, dst); found {
		if lp != nil {
			return lp.SendFrame(frame)
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
	for mac, lp := range p.table.LocalsInVNI(vni) {
		if mac == skipSrc {
			continue
		}
		_ = lp.SendFrame(frame)
	}
	// Dedup identical remote endpoints (same operator may hold many MACs).
	seen := make(map[netip.AddrPort]struct{})
	for mac, addr := range p.table.RemotesInVNI(vni) {
		if mac == skipSrc {
			continue
		}
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		_ = p.sendVXLAN(vni, frame, addr)
	}
}

// sendVXLAN prepends the VXLAN header and writes one UDP datagram.
//
// addr may be a v4-mapped-v6 form (callers often pass the result of
// net.ResolveUDPAddr("udp", ...)). On a dual-stack net.UDPConn
// WriteToUDPAddrPort handles both, but we Unmap so the datagram is
// addressed in its native family.
func (p *Plane) sendVXLAN(vni common.VNI, frame []byte, addr netip.AddrPort) error {
	if p.conn == nil || !addr.IsValid() {
		return nil
	}
	df := common.GetFrame()
	wire := df.EncodeFrame(vni, frame)
	addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
	_, err := p.conn.WriteToUDPAddrPort(wire, addr)
	common.PutFrame(df)
	return err
}

// RxLoop reads VXLAN datagrams one at a time, decodes inline, learns
// the inner source MAC, then dispatches via Forward. Single goroutine,
// no batching, no worker fan-out — keeps it simple and easy to profile.
func (p *Plane) RxLoop() {
	buf := make([]byte, common.MaxPacketSize)
	for {
		select {
		case <-p.done:
			return
		default:
		}

		n, src, err := p.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if n < common.VxlanHeaderSize+common.EthHeaderSize {
			continue
		}
		df := common.GetFrame()
		if err := df.Decode(buf[:n]); err != nil {
			common.PutFrame(df)
			continue
		}
		vni := df.VNI()
		p.table.LearnRemote(vni, df.SrcMAC(), src)
		_ = p.Forward(vni, df.Frame())
		common.PutFrame(df)
	}
}
