package device

import (
	"net"

	singTun "github.com/sagernet/sing-tun"
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

func RoutineReadFromTUN(i int, tun singTun.Tun, OnPacket func(pb *PacketBuffer), pools *Pools) {
	defer func() {
		log.Debugf("Routine: TUN reader - %d - stopped", i)
	}()
	log.Debugf("Routine: TUN reader - %d - started", i)

	buf := make([]byte, 1600)

	for {
		// read packets
		length, readErr := tun.Read(buf)
		if readErr != nil {
			log.Errorf("Failed to read packet from TUN device: %v", readErr)
			break
		}
		if length < 1 {
			log.Debugf("Received packet with length 0 from TUN device")
			continue
		}
		pb := pools.GetPacketBuffer()
		pb.SetPacket(buf[:length])
		OnPacket(pb)
	}
}

func RoutineWriteToTUN() {
	defer func() {
		log.Debugf("Routine: TUN writer - stopped")
	}()

	log.Debugf("Routine: TUN writer - started")

	for pb := range device.queue.outbound.c {
		_, err := device.tun.Write(pb.Packet())
		device.pools.PutPacketBuffer(pb)
		if err != nil {
			log.Errorf("Failed to write packet to TUN device: %v", err)
			break
		}
	}
}
