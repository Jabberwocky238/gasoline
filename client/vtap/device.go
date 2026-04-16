// Package tap implements a userspace virtual TAP device.
//
// External interfaces:
//
//	Upstream   : an OS L3 TUN device (raw IP packets in/out)
//	Downstream : a transport.Conn (Ethernet frames in/out)
//
// On egress (TUN→Conn) the destination MAC is resolved via the userspace
// ARPTable. On miss the IP packet is enqueued in stagedIPPackets[dstIP]
// and an ARP request is emitted (only on the first miss for that IP).
// When an ARP reply arrives the table fires its OnLearn hook and the
// device drains the matching staging queue, wrapping each held packet
// with the freshly learnt destination MAC and shipping it out.
//
// On ingress (Conn→TUN) the Ethernet header is stripped, ARP traffic is
// handled (replies populate the table → trigger drain; requests targeting
// our own IP are answered), IPv4/IPv6 payloads are written to the TUN.
package tap

import (
	"net/netip"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/transport"
	tunPkg "github.com/jabberwocky238/gasoline/tun"
)

// Device is the unified TUN+Conn TAP device.
type Device struct {
	ctx     *common.Gactx // child of the Client's Gactx; carries logger + cancel
	tun     *tunPkg.Tun
	conn    transport.Conn
	selfMAC common.VMAC
	selfIP  netip.Addr
	arp     *ARPTable
	staged  *stagedIPPackets

	keepaliveHook func()

	mu     sync.Mutex
	closed bool
	done   chan struct{}
}

// New constructs a Device. It does not start any goroutines; call Start.
// parent is the Client's Gactx; a child scope is derived so vtap log lines
// inherit vni/vmac and carry component=vtap.
func New(parent *common.Gactx, tun *tunPkg.Tun, conn transport.Conn, selfMAC common.VMAC, selfIP netip.Prefix) *Device {
	d := &Device{
		ctx:     parent.Child(log.Fields{"component": "vtap"}),
		tun:     tun,
		conn:    conn,
		selfMAC: selfMAC,
		selfIP:  selfIP.Addr(),
		arp:     NewARPTable(),
		staged:  newStagedIPPackets(),
		done:    make(chan struct{}),
	}
	// Drain staged packets whenever ARP learns a new (IP → MAC) binding.
	d.arp.SetLearnHook(d.onArpLearn)
	return d
}

// ARP exposes the local ARP table.
func (d *Device) ARP() *ARPTable { return d.arp }

// SelfMAC returns the device's own VMAC.
func (d *Device) SelfMAC() common.VMAC { return d.selfMAC }

// Conn exposes the underlying transport.Conn (used by the client to attach
// out-of-band writers like keepalive).
func (d *Device) Conn() transport.Conn { return d.conn }

// SetKeepaliveHook installs a callback fired by the ingress loop whenever a
// keepalive reply frame addressed to selfMAC is observed.
func (d *Device) SetKeepaliveHook(fn func()) {
	d.mu.Lock()
	d.keepaliveHook = fn
	d.mu.Unlock()
}

// SelfIP returns the device's overlay IP.
func (d *Device) SelfIP() netip.Addr { return d.selfIP }

// PendingStagedCount returns the number of packets currently waiting on ARP.
func (d *Device) PendingStagedCount() int { return d.staged.pendingCount() }

// Start launches the egress (TUN→Conn) and ingress (Conn→TUN) loops.
func (d *Device) Start() {
	go d.egressLoop()
	go d.ingressLoop()
}

// Close stops the loops and closes the underlying TUN/Conn.
func (d *Device) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	close(d.done)
	d.ctx.Cancel()
	if d.conn != nil {
		_ = d.conn.Close()
	}
	if d.tun != nil {
		return d.tun.Close()
	}
	return nil
}

// --------------- ingress (Conn → TUN) ---------------

func (d *Device) ingressLoop() {
	for {
		select {
		case <-d.done:
			return
		default:
		}

		buf := common.GetBuffer()
		n, err := d.conn.ReadPacket(*buf)
		if err != nil {
			common.PutBuffer(buf)
			return
		}
		if n < common.EthHeaderSize {
			common.PutBuffer(buf)
			continue
		}
		d.handleFrame((*buf)[:n])
		common.PutBuffer(buf)
	}
}

func (d *Device) handleFrame(frame []byte) {
	_, _, ethType, payload, ok := common.ParseEth(frame)
	if !ok {
		return
	}
	switch ethType {
	case common.EtherTypeKeepalive:
		if common.IsKeepaliveReply(frame, d.selfMAC) {
			d.mu.Lock()
			hook := d.keepaliveHook
			d.mu.Unlock()
			if hook != nil {
				hook()
			}
		}
	case common.EtherTypeARP:
		d.handleARP(payload)
	case common.EtherTypeIPv4, common.EtherTypeIPv6:
		if _, err := d.tun.Write(payload); err != nil {
			d.ctx.Logger().Errorf("tap: TUN write: %v", err)
		}
	}
}

func (d *Device) handleARP(body []byte) {
	pkt, ok := common.ParseARP(body)
	if !ok {
		return
	}
	// Always learn (sender IP → sender MAC). Set fires the OnLearn hook
	// which drains any staged packets for that IP.
	if pkt.SPA.IsValid() {
		d.arp.Set(pkt.SPA, pkt.SHA)
	}
	if pkt.Op == common.ARPOpRequest && pkt.TPA == d.selfIP {
		reply := common.BuildARPReply(d.selfMAC, d.selfIP, pkt.SHA, pkt.SPA)
		_ = d.conn.WritePacket(reply)
	}
}

// onArpLearn is the hook invoked by ARPTable.Set. Drains the staging
// queue for that IP and ships each held packet with the new MAC.
func (d *Device) onArpLearn(ip netip.Addr, mac common.VMAC) {
	queued := d.staged.drain(ip)
	for _, ipPkt := range queued {
		d.shipIP(ipPkt, mac)
	}
}

// --------------- egress (TUN → Conn) ---------------

func (d *Device) egressLoop() {
	for {
		select {
		case <-d.done:
			return
		default:
		}

		buf := common.GetBuffer()
		n, err := d.tun.Read(*buf)
		if err != nil {
			common.PutBuffer(buf)
			d.ctx.Logger().Errorf("tap: TUN read: %v", err)
			return
		}
		if n < 1 {
			common.PutBuffer(buf)
			continue
		}
		d.handleEgress((*buf)[:n])
		common.PutBuffer(buf)
	}
}

// handleEgress processes one IP packet read from the TUN.
//
// Fast path : ARP hit → wrap & ship synchronously.
// Slow path : ARP miss → copy into staging queue, emit ARP request once
//
//	per destination, return immediately. Drain happens via
//	onArpLearn when the reply arrives.
func (d *Device) handleEgress(ipPkt []byte) {
	dstIP, ok := parseDstIP(ipPkt)
	if !ok {
		return
	}
	if dstMAC, ok := d.arp.Lookup(dstIP); ok {
		d.shipIP(ipPkt, dstMAC)
		return
	}
	queued, firstHit := d.staged.enqueue(dstIP, ipPkt)
	if !queued {
		d.ctx.Logger().Debugf("tap: staged queue full for %s, dropping", dstIP)
		return
	}
	if firstHit {
		req := common.BuildARPRequest(d.selfMAC, d.selfIP, dstIP)
		_ = d.conn.WritePacket(req)
	}
}

func ethTypeFromIP(ipPacket []byte) uint16 {
	if len(ipPacket) == 0 {
		return 0
	}
	switch ipPacket[0] >> 4 {
	case 4:
		return common.EtherTypeIPv4
	case 6:
		return common.EtherTypeIPv6
	}
	return 0
}

// shipIP wraps an IP packet in an Ethernet header and writes one frame to Conn.
func (d *Device) shipIP(ipPkt []byte, dstMAC common.VMAC) {
	ethType := ethTypeFromIP(ipPkt)
	if ethType == 0 {
		return
	}
	frameBuf := common.GetBuffer()
	defer common.PutBuffer(frameBuf)
	frame := (*frameBuf)[:common.EthHeaderSize+len(ipPkt)]
	common.WriteEthHeader(frame, dstMAC, d.selfMAC, ethType)
	copy(frame[common.EthHeaderSize:], ipPkt)
	_ = d.conn.WritePacket(frame)
}

// parseDstIP extracts the destination IP from a raw IPv4/IPv6 packet.
// Used only as a key into stagedIPPackets / ARPTable; the inner payload
// is never inspected beyond this point.
func parseDstIP(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 1 {
		return netip.Addr{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}), true
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}, false
		}
		var a [16]byte
		copy(a[:], pkt[24:40])
		return netip.AddrFrom16(a), true
	}
	return netip.Addr{}, false
}

// Touch keeps the package's time import alive for future TTL/age-out work
// (staged-queue GC, ARP entry expiry). Currently unused but reserved.
var _ = time.Second
