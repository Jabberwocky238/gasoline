package device

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// MessageType 消息类型
type MessageType uint32

const (
	// Data 数据包
	Data MessageType = 1
)

// ProtocolMessage 协议消息结构 (32字节头部 + 数据)
type ProtocolMessage struct {
	// 消息类型 (1字节)
	Type MessageType
	// 保留字段 (1字节)
	Reserved uint8
	// 数据长度 (2字节)
	DataLength uint16
	// 源地址 (4字节 IPv4)
	SourceIP uint32
	// 目的地址 (4字节 IPv4)
	DestIP uint32
	// 时间戳 (8字节)
	Timestamp uint64
	// 随机数 (8字节)
	Nonce uint64
	// 数据部分 (可变长度)
	Data []byte
}

// NewProtocolMessage 创建新的协议消息
func NewProtocolMessage(msgType MessageType, sourceIP, destIP net.IP, data []byte) *ProtocolMessage {
	msg := &ProtocolMessage{
		Type:       msgType,
		Reserved:   0,
		DataLength: uint16(len(data)),
		Timestamp:  uint64(time.Now().UnixNano()),
		Data:       data,
	}

	// 设置IP地址
	if sourceIP != nil {
		msg.SourceIP = ipToUint32(sourceIP)
	}
	if destIP != nil {
		msg.DestIP = ipToUint32(destIP)
	}

	// 生成随机数
	nonceBytes := make([]byte, 8)
	rand.Read(nonceBytes)
	msg.Nonce = binary.LittleEndian.Uint64(nonceBytes)

	return msg
}

// Serialize 序列化消息为字节数组
func (pm *ProtocolMessage) Serialize() []byte {
	// 32字节头部 + 数据长度
	totalLength := 32 + len(pm.Data)
	data := make([]byte, totalLength)

	// 消息类型 (1字节)
	data[0] = byte(pm.Type)

	// 保留字段 (1字节)
	data[1] = pm.Reserved

	// 数据长度 (2字节)
	binary.LittleEndian.PutUint16(data[2:4], pm.DataLength)

	// 源地址 (4字节)
	binary.LittleEndian.PutUint32(data[4:8], pm.SourceIP)

	// 目的地址 (4字节)
	binary.LittleEndian.PutUint32(data[8:12], pm.DestIP)

	// 时间戳 (8字节)
	binary.LittleEndian.PutUint64(data[12:20], pm.Timestamp)

	// 随机数 (8字节)
	binary.LittleEndian.PutUint64(data[20:28], pm.Nonce)

	// 保留字段 (4字节)
	binary.LittleEndian.PutUint32(data[28:32], 0)

	// 数据部分
	copy(data[32:], pm.Data)

	return data
}

// Deserialize 从字节数组反序列化消息
func (pm *ProtocolMessage) Deserialize(data []byte) error {
	if len(data) < 32 {
		return fmt.Errorf("协议消息头部长度不足，期望至少32字节，实际为%d字节", len(data))
	}

	pm.Type = MessageType(data[0])
	pm.Reserved = data[1]
	pm.DataLength = binary.LittleEndian.Uint16(data[2:4])
	pm.SourceIP = binary.LittleEndian.Uint32(data[4:8])
	pm.DestIP = binary.LittleEndian.Uint32(data[8:12])
	pm.Timestamp = binary.LittleEndian.Uint64(data[12:20])
	pm.Nonce = binary.LittleEndian.Uint64(data[20:28])

	// 检查数据长度
	expectedLength := 32 + int(pm.DataLength)
	if len(data) < expectedLength {
		return fmt.Errorf("协议消息数据长度不足，期望%d字节，实际为%d字节", expectedLength, len(data))
	}

	// 提取数据部分
	if pm.DataLength > 0 {
		pm.Data = make([]byte, pm.DataLength)
		copy(pm.Data, data[32:32+pm.DataLength])
	} else {
		pm.Data = nil
	}

	return nil
}

// GetSourceIP 获取源IP地址
func (pm *ProtocolMessage) GetSourceIP() net.IP {
	return uint32ToIP(pm.SourceIP)
}

// GetDestIP 获取目的IP地址
func (pm *ProtocolMessage) GetDestIP() net.IP {
	return uint32ToIP(pm.DestIP)
}

// IsValid 验证消息是否有效
func (pm *ProtocolMessage) IsValid() bool {
	// 检查消息类型是否有效
	if pm.Type != Data {
		return false
	}

	// 检查时间戳是否合理（不能太旧，不能是未来时间）
	now := uint64(time.Now().UnixNano())
	maxAge := uint64(5 * time.Minute) // 5分钟最大年龄

	if pm.Timestamp > now || (now-pm.Timestamp) > maxAge {
		return false
	}

	return true
}

// String 返回消息的字符串表示
func (pm *ProtocolMessage) String() string {
	return fmt.Sprintf("ProtocolMessage{Type:%d, Source:%s, Dest:%s, Timestamp:%d, Nonce:%d}",
		pm.Type, pm.GetSourceIP(), pm.GetDestIP(), pm.Timestamp, pm.Nonce)
}

// ipToUint32 将IPv4地址转换为uint32
func ipToUint32(ip net.IP) uint32 {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ipv4)
}

// uint32ToIP 将uint32转换为IPv4地址
func uint32ToIP(ip uint32) net.IP {
	ipv4 := make(net.IP, 4)
	binary.BigEndian.PutUint32(ipv4, ip)
	return ipv4
}

// HandleInbound 处理从隧道进来的包（外部→TUN）
func (d *Device) HandleInbound(msg *ProtocolMessage, tlsConn *tls.Conn) error {
	// 解析IP头部获取连接信息
	ipHeader, err := ParseIPHeader(msg.Data)
	if err != nil {
		// 静默跳过无法解析的包，但继续处理
		fmt.Printf("无法解析入站IP头部: %v\n", err)
	} else {
		fmt.Printf("处理入站数据包: %s -> %s (协议: %d)\n",
			ipHeader.SourceIP.String(), ipHeader.DestIP.String(), ipHeader.Protocol)

		// 首先检查目标IP是否在peers的AllowedIPs范围内
		if !d.IsIPInAllowedRange(ipHeader.DestIP) {
			fmt.Printf("入站目标IP %s 不在允许范围内\n", ipHeader.DestIP.String())
			return nil
		}

		// 检查是否为广播或多播包
		if IsBroadcastOrMulticast(ipHeader.DestIP) {
			fmt.Printf("跳过入站广播/多播包: %s\n", ipHeader.DestIP.String())
			// 广播包暂时跳过，避免循环
			return nil
		}

		// 创建或更新连接元数据
		metadata := d.connectionManager.GetOrCreateConnection(
			ipHeader.SourceIP,
			ipHeader.DestIP,
			ipHeader.Protocol,
		)

		// 设置端口信息
		metadata.SourcePort = ipHeader.GetSourcePort(msg.Data)
		metadata.DestPort = ipHeader.GetDestPort(msg.Data)

		// 更新统计信息
		metadata.UpdateStats(uint64(len(msg.Data)), 0)

	}

	// 直接透传原始数据包到TUN设备
	fmt.Printf("将数据包写入TUN设备，大小: %d\n", len(msg.Data))
	if err := d.WriteToTUN(msg); err != nil {
		return err
	}

	return nil
}

// WriteToTUN 将协议消息写入TUN设备
func (d *Device) WriteToTUN(msg *ProtocolMessage) error {
	// 协议消息的Data字段包含完整的IP包数据
	ipPacket := msg.Data

	// 写入TUN设备
	_, err := d.tun.Write([][]byte{ipPacket}, 0)
	if err != nil {
		return fmt.Errorf("写入TUN设备失败: %v", err)
	}

	return nil
}
