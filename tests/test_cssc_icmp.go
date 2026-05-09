package tests

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/device/vtep"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport/quic"
)

// TestCSSC_ICMP_QUIC verifies the operator data plane is protocol-agnostic:
// an ICMP Echo Request crafted on clientA reaches clientB intact across the
// two-operator (C-S-S-C) QUIC path. No ICMP responder — we only check that
// proto=1 traffic survives forwarding, which is what would block `ping`
// if the plane ever grew a UDP/TCP filter.
func TestCSSC_ICMP_QUIC(t *testing.T) {
	opA, opB, vni := setupOperators(t, "quic")
	defer opA.Close()
	defer opB.Close()

	tlsConf := quic.InsecureClientTLS()

	connA, resultA, err := quic.NewDialer(common.VMAC{0x02, 0, 0, 0, 0, 0x01}, vni, &auth.NoAuthClient{}, tlsConf).Dial(opA.ClientAddr())
	if err != nil {
		t.Fatalf("ClientA dial: %v", err)
	}
	defer connA.Close()

	connB, resultB, err := quic.NewDialer(common.VMAC{0x02, 0, 0, 0, 0, 0x02}, vni, &auth.NoAuthClient{}, tlsConf).Dial(opB.ClientAddr())
	if err != nil {
		t.Fatalf("ClientB dial: %v", err)
	}
	defer connB.Close()

	clientAIP := resultA.Config.IPPrefix.Addr()
	clientBIP := resultB.Config.IPPrefix.Addr()
	t.Logf("ClientA=%s ClientB=%s", clientAIP, clientBIP)

	waitFor(t, 2*time.Second, func() bool {
		_, _, found := opA.LookupRemoteByVMAC(vni, resultB.VMAC)
		return found
	})

	echoPayload := []byte("hello-icmp-over-gasoline")
	ipPkt := makeICMPv4Echo(clientAIP, clientBIP, 0x1234, 1, echoPayload)
	wire := make([]byte, common.EthHeaderSize+len(ipPkt))
	vtep.WriteEthHeader(wire, resultB.VMAC, resultA.VMAC, vtep.EtherTypeIPv4)
	copy(wire[common.EthHeaderSize:], ipPkt)

	recv := make(chan []byte, 1)
	go func() {
		buf := make([]byte, common.MaxPacketSize)
		n, err := connB.ReadPacket(buf)
		if err != nil || n == 0 {
			return
		}
		cp := make([]byte, n)
		copy(cp, buf[:n])
		recv <- cp
	}()

	if err := connA.WritePacket(wire); err != nil {
		t.Fatalf("send ICMP echo: %v", err)
	}

	var frame []byte
	select {
	case frame = <-recv:
	case <-time.After(3 * time.Second):
		t.Fatal("ICMP packet not received within 3s")
	}

	_, _, ethType, payload, ok := vtep.ParseEth(frame)
	if !ok {
		t.Fatalf("parse eth: short frame %d", len(frame))
	}
	if ethType != vtep.EtherTypeIPv4 {
		t.Fatalf("ethertype: got 0x%04x want 0x%04x", ethType, vtep.EtherTypeIPv4)
	}
	if len(payload) < 20+8 {
		t.Fatalf("ip/icmp too short: %d", len(payload))
	}
	if proto := payload[9]; proto != 1 {
		t.Fatalf("ip proto: got %d want 1 (ICMP)", proto)
	}
	ihl := int(payload[0]&0x0F) * 4
	icmp := payload[ihl:]
	if icmp[0] != 8 || icmp[1] != 0 {
		t.Fatalf("icmp type/code: got %d/%d want 8/0 (echo req)", icmp[0], icmp[1])
	}
	if got := icmp[8:]; !bytes.Equal(got, echoPayload) {
		t.Fatalf("icmp payload: got %q want %q", got, echoPayload)
	}
	t.Logf("ICMP echo (%d-byte payload) delivered A→B via CSSC-QUIC", len(echoPayload))
}

// makeICMPv4Echo builds an IPv4 + ICMP Echo Request packet (no eth header).
// Both the IP and the ICMP checksum fields are populated.
func makeICMPv4Echo(src, dst netip.Addr, id, seq uint16, payload []byte) []byte {
	icmpLen := 8 + len(payload)
	totalLen := 20 + icmpLen
	pkt := make([]byte, totalLen)

	pkt[0] = 0x45 // version=4, IHL=5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64 // TTL
	pkt[9] = 1  // ICMP
	s4 := src.As4()
	d4 := dst.As4()
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:20]))

	icmp := pkt[20:]
	icmp[0] = 8 // Echo Request
	icmp[1] = 0 // code
	binary.BigEndian.PutUint16(icmp[4:6], id)
	binary.BigEndian.PutUint16(icmp[6:8], seq)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], ipChecksum(icmp))
	return pkt
}

func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
