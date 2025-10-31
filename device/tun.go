package device

import (
	"net"
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
		device.queue.routing.queue <- buf[:length]
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
			_, err := device.tun.Write(packet)
			if err != nil {
				device.log.Errorf("Failed to write packet to TUN device: %v", err)
				device.log.Errorf("Packet length: %v", len(packet))
				continue
			}
		}
	}
}
