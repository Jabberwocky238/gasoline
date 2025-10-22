package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"wwww/config"
	"wwww/tun"
)

func main() {
	fmt.Println("Hello, World!")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	cfg, err := config.ParseConfig("tests/client.toml")
	if err != nil {
		fmt.Println("Error parsing config:", err)
		return
	}

	tun, err := tun.NewTun("tun0", cfg)
	if err != nil {
		fmt.Println("Error creating tun:", err)
		return
	}

	err = tun.Start()
	if err != nil {
		fmt.Println("Error starting tun:", err)
		return
	}

	go func() {
		bufs := make([]byte, 1500) // 标准MTU大小
		for {
			n, err := tun.Read(bufs)
			if err != nil {
				fmt.Println("Error reading tun:", err)
				return
			}

			if n > 0 {
				// 调用数据包解析函数
				processPacket(bufs[:n])
			}
		}
	}()

	<-sigChan

	tun.Close()
	fmt.Println("Tun closed")
}

func processPacket(packet []byte) bool {
	fmt.Printf("\n=== 开始解析数据包 (长度: %d 字节) ===\n", len(packet))

	// 显示原始字节数据
	fmt.Println("原始字节数据:")
	for i := 0; i < len(packet); i += 16 {
		fmt.Printf("%04x: ", i)
		// 显示十六进制
		for j := 0; j < 16; j++ {
			if i+j < len(packet) {
				fmt.Printf("%02x ", packet[i+j])
			} else {
				fmt.Printf("   ")
			}
		}
		fmt.Printf(" ")
		// 显示ASCII字符
		for j := 0; j < 16; j++ {
			if i+j < len(packet) {
				if packet[i+j] >= 32 && packet[i+j] <= 126 {
					fmt.Printf("%c", packet[i+j])
				} else {
					fmt.Printf(".")
				}
			} else {
				fmt.Printf(" ")
			}
		}
		fmt.Println()
	}

	// 按字节解析数据包
	if len(packet) == 0 {
		fmt.Println("数据包为空")
		return false
	}

	// 检查是否为IP数据包
	if len(packet) < 20 {
		fmt.Println("数据包太短，不是有效的IP数据包")
		return false
	}

	// 解析IP版本
	version := (packet[0] >> 4) & 0x0F
	fmt.Printf("IP版本: %d\n", version)

	if version == 4 {
		return parseIPv4Packet(packet)
	} else if version == 6 {
		return parseIPv6Packet(packet)
	} else {
		fmt.Printf("未知IP版本: %d\n", version)
		return false
	}
}

// 解析IPv4数据包
func parseIPv4Packet(packet []byte) bool {
	fmt.Println("\n--- IPv4数据包解析 ---")

	if len(packet) < 20 {
		fmt.Println("IPv4数据包太短")
		return false
	}

	// 解析IPv4头部
	version := (packet[0] >> 4) & 0x0F
	ihl := packet[0] & 0x0F
	tos := packet[1]
	totalLength := binary.BigEndian.Uint16(packet[2:4])
	id := binary.BigEndian.Uint16(packet[4:6])
	flags := (packet[6] >> 5) & 0x07
	fragmentOffset := binary.BigEndian.Uint16(packet[6:8]) & 0x1FFF
	ttl := packet[8]
	protocol := packet[9]
	checksum := binary.BigEndian.Uint16(packet[10:12])

	// 解析IP地址
	srcIP := fmt.Sprintf("%d.%d.%d.%d", packet[12], packet[13], packet[14], packet[15])
	dstIP := fmt.Sprintf("%d.%d.%d.%d", packet[16], packet[17], packet[18], packet[19])

	fmt.Printf("版本: %d\n", version)
	fmt.Printf("头部长度: %d (实际: %d 字节)\n", ihl, ihl*4)
	fmt.Printf("服务类型: 0x%02x\n", tos)
	fmt.Printf("总长度: %d 字节\n", totalLength)
	fmt.Printf("标识: 0x%04x\n", id)
	fmt.Printf("标志: %d\n", flags)
	fmt.Printf("片偏移: %d\n", fragmentOffset)
	fmt.Printf("生存时间: %d\n", ttl)
	fmt.Printf("协议: %d (%s)\n", protocol, getProtocolName(protocol))
	fmt.Printf("头部校验和: 0x%04x\n", checksum)
	fmt.Printf("源IP: %s\n", srcIP)
	fmt.Printf("目标IP: %s\n", dstIP)

	// 解析选项（如果有）
	headerLen := int(ihl * 4)
	if ihl > 5 {
		fmt.Printf("选项长度: %d 字节\n", headerLen-20)
		fmt.Printf("选项数据: ")
		for i := 20; i < headerLen; i++ {
			fmt.Printf("%02x ", packet[i])
		}
		fmt.Println()
	}

	// 解析载荷
	if len(packet) > headerLen {
		payload := packet[headerLen:]
		fmt.Printf("载荷长度: %d 字节\n", len(payload))

		// 根据协议类型进一步解析
		switch protocol {
		case 1: // ICMP
			parseICMPPacket(payload)
		case 6: // TCP
			parseTCPPacket(payload)
		case 17: // UDP
			parseUDPPacket(payload)
		default:
			fmt.Printf("载荷数据: ")
			for i := 0; i < len(payload) && i < 32; i++ {
				fmt.Printf("%02x ", payload[i])
			}
			if len(payload) > 32 {
				fmt.Printf("...")
			}
			fmt.Println()
		}
	}

	return true
}

// 解析IPv6数据包
func parseIPv6Packet(packet []byte) bool {
	fmt.Println("\n--- IPv6数据包解析 ---")

	if len(packet) < 40 {
		fmt.Println("IPv6数据包太短")
		return false
	}

	// 解析IPv6头部
	version := (packet[0] >> 4) & 0x0F
	trafficClass := ((packet[0] & 0x0F) << 4) | ((packet[1] >> 4) & 0x0F)
	flowLabel := binary.BigEndian.Uint32(packet[0:4]) & 0x000FFFFF
	payloadLen := binary.BigEndian.Uint16(packet[4:6])
	nextHeader := packet[6]
	hopLimit := packet[7]

	// 解析IP地址
	srcIP := fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		packet[8], packet[9], packet[10], packet[11], packet[12], packet[13], packet[14], packet[15],
		packet[16], packet[17], packet[18], packet[19], packet[20], packet[21], packet[22], packet[23])

	dstIP := fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		packet[24], packet[25], packet[26], packet[27], packet[28], packet[29], packet[30], packet[31],
		packet[32], packet[33], packet[34], packet[35], packet[36], packet[37], packet[38], packet[39])

	fmt.Printf("版本: %d\n", version)
	fmt.Printf("流量类别: 0x%02x\n", trafficClass)
	fmt.Printf("流标签: 0x%05x\n", flowLabel)
	fmt.Printf("载荷长度: %d 字节\n", payloadLen)
	fmt.Printf("下一个头部: %d (%s)\n", nextHeader, getProtocolName(nextHeader))
	fmt.Printf("跳数限制: %d\n", hopLimit)
	fmt.Printf("源IP: %s\n", srcIP)
	fmt.Printf("目标IP: %s\n", dstIP)

	// 解析载荷
	if len(packet) > 40 {
		payload := packet[40:]
		fmt.Printf("载荷长度: %d 字节\n", len(payload))

		// 根据协议类型进一步解析
		switch nextHeader {
		case 1: // ICMP
			parseICMPPacket(payload)
		case 6: // TCP
			parseTCPPacket(payload)
		case 17: // UDP
			parseUDPPacket(payload)
		case 58: // ICMPv6
			parseICMPv6Packet(payload)
		default:
			fmt.Printf("载荷数据: ")
			for i := 0; i < len(payload) && i < 32; i++ {
				fmt.Printf("%02x ", payload[i])
			}
			if len(payload) > 32 {
				fmt.Printf("...")
			}
			fmt.Println()
		}
	}

	return true
}

// 解析ICMP数据包
func parseICMPPacket(packet []byte) {
	fmt.Println("\n--- ICMP数据包解析 ---")

	if len(packet) < 8 {
		fmt.Println("ICMP数据包太短")
		return
	}

	icmpType := packet[0]
	icmpCode := packet[1]
	checksum := binary.BigEndian.Uint16(packet[2:4])

	fmt.Printf("类型: %d\n", icmpType)
	fmt.Printf("代码: %d\n", icmpCode)
	fmt.Printf("校验和: 0x%04x\n", checksum)

	if len(packet) > 8 {
		fmt.Printf("数据: ")
		for i := 8; i < len(packet) && i < 24; i++ {
			fmt.Printf("%02x ", packet[i])
		}
		if len(packet) > 24 {
			fmt.Printf("...")
		}
		fmt.Println()
	}
}

// 解析ICMPv6数据包
func parseICMPv6Packet(packet []byte) {
	fmt.Println("\n--- ICMPv6数据包解析 ---")

	if len(packet) < 8 {
		fmt.Println("ICMPv6数据包太短")
		return
	}

	icmpType := packet[0]
	icmpCode := packet[1]
	checksum := binary.BigEndian.Uint16(packet[2:4])

	fmt.Printf("类型: %d\n", icmpType)
	fmt.Printf("代码: %d\n", icmpCode)
	fmt.Printf("校验和: 0x%04x\n", checksum)

	if len(packet) > 8 {
		fmt.Printf("数据: ")
		for i := 8; i < len(packet) && i < 24; i++ {
			fmt.Printf("%02x ", packet[i])
		}
		if len(packet) > 24 {
			fmt.Printf("...")
		}
		fmt.Println()
	}
}

// 解析TCP数据包
func parseTCPPacket(packet []byte) {
	fmt.Println("\n--- TCP数据包解析 ---")

	if len(packet) < 20 {
		fmt.Println("TCP数据包太短")
		return
	}

	srcPort := binary.BigEndian.Uint16(packet[0:2])
	dstPort := binary.BigEndian.Uint16(packet[2:4])
	seqNum := binary.BigEndian.Uint32(packet[4:8])
	ackNum := binary.BigEndian.Uint32(packet[8:12])
	headerLen := (packet[12] >> 4) & 0x0F
	flags := packet[13]
	windowSize := binary.BigEndian.Uint16(packet[14:16])
	checksum := binary.BigEndian.Uint16(packet[16:18])
	urgentPtr := binary.BigEndian.Uint16(packet[18:20])

	fmt.Printf("源端口: %d\n", srcPort)
	fmt.Printf("目标端口: %d\n", dstPort)
	fmt.Printf("序列号: %d\n", seqNum)
	fmt.Printf("确认号: %d\n", ackNum)
	fmt.Printf("头部长度: %d (实际: %d 字节)\n", headerLen, headerLen*4)
	fmt.Printf("标志: 0x%02x\n", flags)
	fmt.Printf("窗口大小: %d\n", windowSize)
	fmt.Printf("校验和: 0x%04x\n", checksum)
	fmt.Printf("紧急指针: %d\n", urgentPtr)

	// 解析标志位
	fmt.Printf("标志位: ")
	if flags&0x80 != 0 {
		fmt.Printf("CWR ")
	}
	if flags&0x40 != 0 {
		fmt.Printf("ECE ")
	}
	if flags&0x20 != 0 {
		fmt.Printf("URG ")
	}
	if flags&0x10 != 0 {
		fmt.Printf("ACK ")
	}
	if flags&0x08 != 0 {
		fmt.Printf("PSH ")
	}
	if flags&0x04 != 0 {
		fmt.Printf("RST ")
	}
	if flags&0x02 != 0 {
		fmt.Printf("SYN ")
	}
	if flags&0x01 != 0 {
		fmt.Printf("FIN ")
	}
	fmt.Println()

	// 解析载荷
	headerLenBytes := int(headerLen * 4)
	if len(packet) > headerLenBytes {
		payload := packet[headerLenBytes:]
		fmt.Printf("载荷长度: %d 字节\n", len(payload))
		fmt.Printf("载荷数据: ")
		for i := 0; i < len(payload) && i < 32; i++ {
			fmt.Printf("%02x ", payload[i])
		}
		if len(payload) > 32 {
			fmt.Printf("...")
		}
		fmt.Println()
	}
}

// 解析UDP数据包
func parseUDPPacket(packet []byte) {
	fmt.Println("\n--- UDP数据包解析 ---")

	if len(packet) < 8 {
		fmt.Println("UDP数据包太短")
		return
	}

	srcPort := binary.BigEndian.Uint16(packet[0:2])
	dstPort := binary.BigEndian.Uint16(packet[2:4])
	length := binary.BigEndian.Uint16(packet[4:6])
	checksum := binary.BigEndian.Uint16(packet[6:8])

	fmt.Printf("源端口: %d\n", srcPort)
	fmt.Printf("目标端口: %d\n", dstPort)
	fmt.Printf("长度: %d 字节\n", length)
	fmt.Printf("校验和: 0x%04x\n", checksum)

	// 解析载荷
	if len(packet) > 8 {
		payload := packet[8:]
		fmt.Printf("载荷长度: %d 字节\n", len(payload))
		fmt.Printf("载荷数据: ")
		for i := 0; i < len(payload) && i < 32; i++ {
			fmt.Printf("%02x ", payload[i])
		}
		if len(payload) > 32 {
			fmt.Printf("...")
		}
		fmt.Println()
	}
}

// 获取协议名称
func getProtocolName(protocol uint8) string {
	switch protocol {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 58:
		return "ICMPv6"
	default:
		return "Unknown"
	}
}
