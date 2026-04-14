// Package tap implements a userspace virtual TAP device.
//
// A Device has two external interfaces:
//
//	Upstream   : an OS L3 TUN device (raw IP packets in/out)
//	Downstream : a transport.Conn (Ethernet frames in/out)
//
// On egress (TUN→Conn): each IP packet is wrapped in an Ethernet header.
// The destination MAC is resolved via the userspace ARPTable; on miss the
// device emits a standard IPv4 ARP request and queues the packet pending
// resolution.
//
// On ingress (Conn→TUN): the Ethernet header is stripped, ARP traffic is
// intercepted (replies populate the ARP table; requests targeting the
// local IP are answered), and IPv4/IPv6 payloads are written to the TUN.
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

const arpResolveTimeout = 2 * time.Second

// Device is the unified TUN+Conn TAP device.
type Device struct {
	tun     *tunPkg.Tun
	conn    transport.Conn
	selfMAC common.VMAC
	selfIP  netip.Addr
	arp     *ARPTable

	mu     sync.Mutex
	closed bool
	done   chan struct{}
}

// New constructs a Device. It does not start any goroutines; call Start.
func New(tun *tunPkg.Tun, conn transport.Conn, selfMAC common.VMAC, selfIP netip.Prefix) *Device {
	return &Device{
		tun:     tun,
		conn:    conn,
		selfMAC: selfMAC,
		selfIP:  selfIP.Addr(),
		arp:     NewARPTable(),
		done:    make(chan struct{}),
	}
}

// ARP exposes the local ARP table (for seeding, inspection, tooling).
func (d *Device) ARP() *ARPTable { return d.arp }

// SelfMAC returns the device's own VMAC.
func (d *Device) SelfMAC() common.VMAC { return d.selfMAC }

// SelfIP returns the device's overlay IP.
func (d *Device) SelfIP() netip.Addr { return d.selfIP }

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

// handleFrame processes one inbound Ethernet frame.
func (d *Device) handleFrame(frame []byte) {
	_, _, ethType, payload, ok := common.ParseEth(frame)
	if !ok {
		return
	}
	switch ethType {
	case common.EtherTypeARP:
		d.handleARP(payload)
	case common.EtherTypeIPv4, common.EtherTypeIPv6:
		if _, err := d.tun.Write(payload); err != nil {
			log.Errorf("tap: TUN write: %v", err)
		}
	}
}

// handleARP processes an inbound ARP packet body.
func (d *Device) handleARP(body []byte) {
	pkt, ok := common.ParseARP(body)
	if !ok {
		return
	}
	// Always learn (sender IP → sender MAC).
	if pkt.SPA.IsValid() {
		d.arp.Set(pkt.SPA, pkt.SHA)
	}
	if pkt.Op == common.ARPOpRequest && pkt.TPA == d.selfIP {
		reply := common.BuildARPReply(d.selfMAC, d.selfIP, pkt.SHA, pkt.SPA)
		_ = d.conn.WritePacket(reply)
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

		ipBuf := common.GetBuffer()
		n, err := d.tun.Read(*ipBuf)
		if err != nil {
			common.PutBuffer(ipBuf)
			log.Errorf("tap: TUN read: %v", err)
			return
		}
		if n < 1 {
			common.PutBuffer(ipBuf)
			continue
		}
		go d.sendIP(ipBuf, n)
	}
}

// sendIP wraps an IP packet (ipBuf[:n]) with an Ethernet header (resolving
// via ARP if needed) and ships it through the Conn. Owns ipBuf.
func (d *Device) sendIP(ipBuf *[]byte, n int) {
	defer common.PutBuffer(ipBuf)

	ipPkt := (*ipBuf)[:n]
	dstIP, ok := parseDstIP(ipPkt)
	if !ok {
		return
	}
	ethType := common.EthTypeFromIP(ipPkt)
	if ethType == 0 {
		return
	}

	dstMAC, ok := d.arp.Lookup(dstIP)
	if !ok {
		req := common.BuildARPRequest(d.selfMAC, d.selfIP, dstIP)
		_ = d.conn.WritePacket(req)
		select {
		case mac := <-d.arp.WaitFor(dstIP, arpResolveTimeout):
			var zero common.VMAC
			if mac == zero {
				log.Debugf("tap: ARP timeout for %s", dstIP)
				return
			}
			dstMAC = mac
		case <-d.done:
			return
		}
	}

	frameBuf := common.GetBuffer()
	defer common.PutBuffer(frameBuf)
	frame := (*frameBuf)[:common.EthHeaderSize+n]
	common.WriteEthHeader(frame, dstMAC, d.selfMAC, ethType)
	copy(frame[common.EthHeaderSize:], ipPkt)
	_ = d.conn.WritePacket(frame)
}

// parseDstIP extracts the destination IP from a raw IPv4/IPv6 packet.
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
