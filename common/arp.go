package common

import (
	"encoding/binary"
	"net/netip"
)

// Standard IPv4 ARP wire format (RFC 826).
//
//   [HType:2 = 1 (Ethernet)]
//   [PType:2 = 0x0800 (IPv4)]
//   [HLen:1  = 6]
//   [PLen:1  = 4]
//   [Op:2    = 1 (request) or 2 (reply)]
//   [SHA:6]  sender hardware address
//   [SPA:4]  sender protocol address
//   [THA:6]  target hardware address (zero in a request)
//   [TPA:4]  target protocol address
//
// Total: 28 bytes inside an Ethernet frame with EtherType=0x0806.

const (
	EtherTypeARP = 0x0806

	ARPHTypeEthernet = 1
	ARPPTypeIPv4     = 0x0800
	ARPHLen          = 6
	ARPPLen          = 4

	ARPOpRequest = 1
	ARPOpReply   = 2

	ARPPacketSize = 28
)

// ARPPacket is the parsed view of an ARP frame body.
type ARPPacket struct {
	Op  uint16
	SHA VMAC
	SPA netip.Addr // always IPv4
	THA VMAC
	TPA netip.Addr // always IPv4
}

// BuildARPRequest builds a full Ethernet frame carrying an ARP "who has TPA?
// tell SPA" request, broadcast to FF:FF:FF:FF:FF:FF.
func BuildARPRequest(senderMAC VMAC, senderIP, targetIP netip.Addr) []byte {
	frame := make([]byte, EthHeaderSize+ARPPacketSize)
	WriteEthHeader(frame, EthBroadcastMAC, senderMAC, EtherTypeARP)
	writeARP(frame[EthHeaderSize:], ARPOpRequest, senderMAC, senderIP, VMAC{}, targetIP)
	return frame
}

// BuildARPReply builds a full Ethernet frame carrying an ARP reply
// "TPA is at THA" addressed unicast back to the requester.
func BuildARPReply(senderMAC VMAC, senderIP netip.Addr, targetMAC VMAC, targetIP netip.Addr) []byte {
	frame := make([]byte, EthHeaderSize+ARPPacketSize)
	WriteEthHeader(frame, targetMAC, senderMAC, EtherTypeARP)
	writeARP(frame[EthHeaderSize:], ARPOpReply, senderMAC, senderIP, targetMAC, targetIP)
	return frame
}

func writeARP(buf []byte, op uint16, sha VMAC, spa netip.Addr, tha VMAC, tpa netip.Addr) {
	binary.BigEndian.PutUint16(buf[0:2], ARPHTypeEthernet)
	binary.BigEndian.PutUint16(buf[2:4], ARPPTypeIPv4)
	buf[4] = ARPHLen
	buf[5] = ARPPLen
	binary.BigEndian.PutUint16(buf[6:8], op)
	copy(buf[8:14], sha[:])
	if spa.Is4() {
		s4 := spa.As4()
		copy(buf[14:18], s4[:])
	}
	copy(buf[18:24], tha[:])
	if tpa.Is4() {
		t4 := tpa.As4()
		copy(buf[24:28], t4[:])
	}
}

// ParseARP parses the ARP body (28 bytes after the Ethernet header).
func ParseARP(arpBody []byte) (*ARPPacket, bool) {
	if len(arpBody) < ARPPacketSize {
		return nil, false
	}
	if binary.BigEndian.Uint16(arpBody[0:2]) != ARPHTypeEthernet ||
		binary.BigEndian.Uint16(arpBody[2:4]) != ARPPTypeIPv4 ||
		arpBody[4] != ARPHLen ||
		arpBody[5] != ARPPLen {
		return nil, false
	}
	p := &ARPPacket{Op: binary.BigEndian.Uint16(arpBody[6:8])}
	copy(p.SHA[:], arpBody[8:14])
	p.SPA = netip.AddrFrom4([4]byte{arpBody[14], arpBody[15], arpBody[16], arpBody[17]})
	copy(p.THA[:], arpBody[18:24])
	p.TPA = netip.AddrFrom4([4]byte{arpBody[24], arpBody[25], arpBody[26], arpBody[27]})
	return p, true
}
