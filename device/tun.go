package device

import (
	"net"

	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	IPv4offsetTotalLength = 2
	IPv4offsetSrc         = 12
	IPv4offsetDst         = IPv4offsetSrc + net.IPv4len
)

const (
	IPv6offsetPayloadLength = 4
	IPv6offsetSrc           = 8
	IPv6offsetDst           = IPv6offsetSrc + net.IPv6len
)

func (device *Device) RoutineReadFromTUN() {
	defer func() {
		device.log.Debugf("Routine: TUN reader - stopped")
	}()

	device.log.Debugf("Routine: TUN reader - started")

	var (
		buf = make([]byte, 1600)
	)

	for {
		// read packets
		length, readErr := device.tun.Read(buf)
		if readErr != nil {
			device.log.Errorf("Failed to read packet from TUN device: %v", readErr)
			continue
		}
		if length < 1 {
			device.log.Debugf("Received packet with length 0 from TUN device")
			continue
		}
		ipVersion := buf[0] >> 4

		// lookup peer
		var peer *Peer
		switch ipVersion {
		case 4:
			if length < ipv4.HeaderLen {
				continue
			}
			// showPacket(device.log, buf, layers.LayerTypeIPv4, "inbound")
			dst := buf[IPv4offsetDst : IPv4offsetDst+net.IPv4len]
			peer = device.allowedips.Lookup(dst)

		case 6:
			if length < ipv6.HeaderLen {
				continue
			}
			// showPacket(device.log, buf, layers.LayerTypeIPv6, "inbound")
			dst := buf[IPv6offsetDst : IPv6offsetDst+net.IPv6len]
			peer = device.allowedips.Lookup(dst)

		default:
			device.log.Debugf("Received packet with unknown IP version")
		}

		if peer == nil {
			continue
		}
		peer.queue.inbound.queue <- buf[:length]
	}
}

func (device *Device) RoutineWriteToTUN() {
	defer func() {
		device.log.Debugf("Routine: TUN writer - stopped")
	}()

	device.log.Debugf("Routine: TUN writer - started")

	for {
		select {
		case packet := <-device.queue.outbound.queue:
			device.log.Debugf("RoutineWriteToTUN: received packet, length: %d", len(packet))
			ipVersion := packet[0] >> 4
			switch ipVersion {
			case 4:
				showPacket(device.log, packet, layers.LayerTypeIPv4, "outbound")
			case 6:
				showPacket(device.log, packet, layers.LayerTypeIPv6, "outbound")
			default:
				device.log.Debugf("Unknown IP version")
			}
			_, err := device.tun.Write(packet)
			if err != nil {
				device.log.Errorf("Failed to write packet to TUN device: %v", err)
				device.log.Errorf("Packet length: %v", len(packet))
				continue
			}
		}
	}
}
