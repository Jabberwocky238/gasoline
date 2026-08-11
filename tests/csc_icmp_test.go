package tests

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/transport/quic"
)

// TestCSC_ICMP_QUIC verifies the operator data plane is protocol-
// agnostic: an ICMP Echo Request crafted on clientA reaches clientB
// intact across the single-operator (C-S-C) QUIC path. No ICMP
// responder — we only check that proto=1 traffic survives the L3
// forwarder, which is what would block `ping` if forwardFrame ever
// grew a UDP/TCP filter.
func TestCSC_ICMP_QUIC(t *testing.T) {
	bs := startBenchOperator(t, "quic")
	defer bs.op.Close()

	tlsConf := quic.InsecureClientTLS()

	cfgA := protocol.NewPresetSessionConfig(bs.cidA, bs.vni)
	connA, _, err := quic.NewDialer(cfgA, bs.idA(), tlsConf).Dial(bs.op.ClientAddr())
	if err != nil {
		t.Fatalf("ClientA dial: %v", err)
	}
	defer connA.Close()

	cfgB := protocol.NewPresetSessionConfig(bs.cidB, bs.vni)
	connB, _, err := quic.NewDialer(cfgB, bs.idB(), tlsConf).Dial(bs.op.ClientAddr())
	if err != nil {
		t.Fatalf("ClientB dial: %v", err)
	}
	defer connB.Close()

	srcIP := bs.pfxA.Addr()
	dstIP := bs.pfxB.Addr()
	t.Logf("ClientA=%s ClientB=%s", srcIP, dstIP)

	echoPayload := []byte("hello-icmp-over-gasoline")
	ipPkt := makeICMPv4Echo(srcIP, dstIP, 0x1234, 1, echoPayload)

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

	if err := connA.WritePacket(ipPkt); err != nil {
		t.Fatalf("send ICMP echo: %v", err)
	}

	var frame []byte
	select {
	case frame = <-recv:
	case <-time.After(3 * time.Second):
		t.Fatal("ICMP packet not received within 3s")
	}

	if len(frame) < 20+8 {
		t.Fatalf("ip/icmp too short: %d", len(frame))
	}
	if version := frame[0] >> 4; version != 4 {
		t.Fatalf("ip version: got %d want 4", version)
	}
	if proto := frame[9]; proto != 1 {
		t.Fatalf("ip proto: got %d want 1 (ICMP)", proto)
	}
	ihl := int(frame[0]&0x0F) * 4
	icmp := frame[ihl:]
	if icmp[0] != 8 || icmp[1] != 0 {
		t.Fatalf("icmp type/code: got %d/%d want 8/0 (echo req)", icmp[0], icmp[1])
	}
	if got := icmp[8:]; !bytes.Equal(got, echoPayload) {
		t.Fatalf("icmp payload: got %q want %q", got, echoPayload)
	}
	t.Logf("ICMP echo (%d-byte payload) delivered A→B via CSC-QUIC", len(echoPayload))
}

// makeICMPv4Echo builds an IPv4 + ICMP Echo Request packet. Both the
// IP and ICMP checksum fields are populated so receivers won't drop
// the packet for being malformed.
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
