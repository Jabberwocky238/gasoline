package device

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
)

func showPacket(logger *logrus.Logger, packet []byte, layerType gopacket.LayerType, extraInfo string) {
	// packet could be IPv4 or IPv6
	packetObj := gopacket.NewPacket(packet, layerType, gopacket.Default)
	layer := packetObj.Layer(layerType)
	if layer == nil {
		logger.Debugf("Packet is nil")
		return
	}
	switch layerType {
	case layers.LayerTypeIPv4:
		ipv4Layer := layer.(*layers.IPv4)
		from := ipv4Layer.SrcIP.String()
		to := ipv4Layer.DstIP.String()
		protocol := ipv4Layer.Protocol.String()
		length := ipv4Layer.Length
		logger.Debugf("%s, IPv4 packet: %s -> %s, %s, length: %d", extraInfo, from, to, protocol, length)
	case layers.LayerTypeIPv6:
		ipv6Layer := layer.(*layers.IPv6)
		from := ipv6Layer.SrcIP.String()
		to := ipv6Layer.DstIP.String()
		protocol := ipv6Layer.NextHeader
		length := ipv6Layer.Length
		logger.Debugf("%s, IPv6 packet: %s -> %s, %s, length: %d", extraInfo, from, to, protocol, length)
	default:
		logger.Debugf("Unknown packet: %v", layer)
	}
}

func manualPacket(fromIP net.IP, toIP net.IP) []byte {
	// 创建UDP载荷数据 - 包含时间戳和源IP信息
	timestamp := time.Now().Unix()
	payload := fmt.Sprintf("Boardcast from %s to %s at %d", fromIP.String(), toIP.String(), timestamp)

	// 创建UDP层
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(12345), // 源端口
		DstPort: layers.UDPPort(54321), // 目标端口
	}

	// 创建IPv4层
	ipv4 := &layers.IPv4{
		Version:    4,
		IHL:        5, // 20字节头部
		TOS:        0,
		Length:     uint16(20 + 8 + len(payload)), // IP头部 + UDP头部 + 数据
		Id:         1,
		Flags:      0,
		FragOffset: 0,
		TTL:        64,
		Protocol:   layers.IPProtocolUDP,
		SrcIP:      fromIP,
		DstIP:      toIP,
	}

	// 设置UDP的网络层用于校验和计算
	udp.SetNetworkLayerForChecksum(ipv4)

	// 序列化包
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err := gopacket.SerializeLayers(buffer, options, ipv4, udp, gopacket.Payload(payload))
	if err != nil {
		return nil
	}

	return buffer.Bytes()
}
