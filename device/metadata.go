package device

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// ConnectionMetadata 连接元数据
type ConnectionMetadata struct {
	// 基本信息
	SourceIP   net.IP
	DestIP     net.IP
	Protocol   uint8
	SourcePort uint16
	DestPort   uint16

	// 时间信息
	FirstSeen time.Time
	LastSeen  time.Time

	// 统计信息
	PacketsIn  uint64
	PacketsOut uint64
	BytesIn    uint64
	BytesOut   uint64

	// 连接状态
	IsActive bool

	// 对端信息
	PeerKey string
}

// NewConnectionMetadata 创建新的连接元数据
func NewConnectionMetadata(sourceIP, destIP net.IP, protocol uint8) *ConnectionMetadata {
	now := time.Now()
	return &ConnectionMetadata{
		SourceIP:  sourceIP,
		DestIP:    destIP,
		Protocol:  protocol,
		FirstSeen: now,
		LastSeen:  now,
		IsActive:  true,
	}
}

// UpdateStats 更新统计信息
func (cm *ConnectionMetadata) UpdateStats(bytesIn, bytesOut uint64) {
	cm.LastSeen = time.Now()
	cm.BytesIn += bytesIn
	cm.BytesOut += bytesOut
	if bytesIn > 0 {
		cm.PacketsIn++
	}
	if bytesOut > 0 {
		cm.PacketsOut++
	}
}

// String 返回连接元数据的字符串表示
func (cm *ConnectionMetadata) String() string {
	return fmt.Sprintf("Connection{Source:%s:%d, Dest:%s:%d, Protocol:%d, Packets:%d/%d, Bytes:%d/%d}",
		cm.SourceIP, cm.SourcePort, cm.DestIP, cm.DestPort, cm.Protocol,
		cm.PacketsIn, cm.PacketsOut, cm.BytesIn, cm.BytesOut)
}

// IPHeader IP头部结构（支持IPv4和IPv6）
type IPHeader struct {
	Version    uint8
	IHL        uint8
	TOS        uint8
	Length     uint16
	ID         uint16
	Flags      uint8
	FragOffset uint16
	TTL        uint8
	Protocol   uint8
	Checksum   uint16
	SourceIP   net.IP
	DestIP     net.IP
	IsIPv6     bool
	// IPv6特有字段
	TrafficClass uint8
	FlowLabel    uint32
	PayloadLen   uint16
	NextHeader   uint8
	HopLimit     uint8
}

// ParseIPHeader 解析IP头部（支持IPv4和IPv6）
func ParseIPHeader(data []byte) (*IPHeader, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("IP包长度不足，至少需要20字节")
	}

	version := data[0] >> 4

	if version == 4 {
		// IPv4包
		if len(data) < 20 {
			return nil, fmt.Errorf("IPv4包长度不足")
		}

		header := &IPHeader{
			Version:    version,
			IHL:        data[0] & 0x0F,
			TOS:        data[1],
			Length:     binary.BigEndian.Uint16(data[2:4]),
			ID:         binary.BigEndian.Uint16(data[4:6]),
			Flags:      data[6] >> 5,
			FragOffset: binary.BigEndian.Uint16(data[6:8]) & 0x1FFF,
			TTL:        data[8],
			Protocol:   data[9],
			Checksum:   binary.BigEndian.Uint16(data[10:12]),
			SourceIP:   net.IP(data[12:16]),
			DestIP:     net.IP(data[16:20]),
			IsIPv6:     false,
		}

		// 验证IPv4头部
		if header.IHL < 5 {
			return nil, fmt.Errorf("IPv4头部长度不足，IHL: %d", header.IHL)
		}

		return header, nil
	} else if version == 6 {
		// IPv6包
		if len(data) < 40 {
			return nil, fmt.Errorf("IPv6包长度不足")
		}

		header := &IPHeader{
			Version:      version,
			IsIPv6:       true,
			TrafficClass: (data[0]&0x0F)<<4 | (data[1] >> 4),
			FlowLabel:    binary.BigEndian.Uint32(data[0:4]) & 0x000FFFFF,
			PayloadLen:   binary.BigEndian.Uint16(data[4:6]),
			NextHeader:   data[6],
			HopLimit:     data[7],
			SourceIP:     net.IP(data[8:24]),
			DestIP:       net.IP(data[24:40]),
			Protocol:     data[6], // NextHeader在IPv6中相当于Protocol
		}

		return header, nil
	} else {
		return nil, fmt.Errorf("不支持的IP版本: %d", version)
	}
}

// IsBroadcastOrMulticast 检查是否为广播或多播包
func IsBroadcastOrMulticast(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// 检查IPv4广播和多播
	if ipv4 := ip.To4(); ipv4 != nil {
		// 检查多播地址 (224.0.0.0/4)
		if ipv4[0] >= 224 && ipv4[0] <= 239 {
			return true
		}
		// 检查本地链路广播 (169.254.0.0/16)
		if ipv4[0] == 169 && ipv4[1] == 254 {
			return true
		}
		// 检查有限广播 (255.255.255.255)
		if ipv4[0] == 255 && ipv4[1] == 255 && ipv4[2] == 255 && ipv4[3] == 255 {
			return true
		}
	} else if len(ip) == 16 {
		// 检查IPv6多播地址 (ff00::/8)
		if ip[0] == 0xff {
			return true
		}
		// 检查IPv6本地链路地址 (fe80::/10)
		if ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
			return true
		}
		// 检查IPv6站点本地地址 (fec0::/10)
		if ip[0] == 0xfe && (ip[1]&0xc0) == 0xc0 {
			return true
		}
	}

	return false
}

// IsIPInAllowedRange 检查IP是否在peers的AllowedIPs范围内
func (d *Device) IsIPInAllowedRange(ip net.IP) bool {
	d.indexMutex.RLock()
	defer d.indexMutex.RUnlock()

	// 遍历所有对端，检查IP是否在允许的IP范围内
	for _, peer := range d.indexMap {
		if peer.AllowedIPs.Contains(ip) {
			return true
		}
	}
	return false
}

// GetSourcePort 从IP包中提取源端口（TCP/UDP）
func (h *IPHeader) GetSourcePort(data []byte) uint16 {
	var offset int
	if h.IsIPv6 {
		// IPv6: 固定40字节头部
		offset = 40
	} else {
		// IPv4: 可变长度头部
		offset = int(h.IHL * 4)
	}

	if len(data) < offset+2 {
		return 0
	}
	return binary.BigEndian.Uint16(data[offset : offset+2])
}

// GetDestPort 从IP包中提取目的端口（TCP/UDP）
func (h *IPHeader) GetDestPort(data []byte) uint16 {
	var offset int
	if h.IsIPv6 {
		// IPv6: 固定40字节头部
		offset = 40
	} else {
		// IPv4: 可变长度头部
		offset = int(h.IHL * 4)
	}

	if len(data) < offset+4 {
		return 0
	}
	return binary.BigEndian.Uint16(data[offset+2 : offset+4])
}

// ConnectionManager 连接管理器
type ConnectionManager struct {
	connections map[string]*ConnectionMetadata
	mutex       sync.RWMutex
}

// NewConnectionManager 创建连接管理器
func NewConnectionManager() *ConnectionManager {
	return &ConnectionManager{
		connections: make(map[string]*ConnectionMetadata),
	}
}

// GetOrCreateConnection 获取或创建连接元数据
func (cm *ConnectionManager) GetOrCreateConnection(sourceIP, destIP net.IP, protocol uint8) *ConnectionMetadata {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	// 创建连接键
	key := fmt.Sprintf("%s:%s:%d", sourceIP.String(), destIP.String(), protocol)

	// 查找现有连接
	if conn, exists := cm.connections[key]; exists {
		conn.LastSeen = time.Now()
		return conn
	}

	// 创建新连接
	conn := NewConnectionMetadata(sourceIP, destIP, protocol)
	cm.connections[key] = conn
	return conn
}

// GetConnection 获取连接元数据
func (cm *ConnectionManager) GetConnection(sourceIP, destIP net.IP, protocol uint8) *ConnectionMetadata {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	key := fmt.Sprintf("%s:%s:%d", sourceIP.String(), destIP.String(), protocol)
	return cm.connections[key]
}

// RemoveConnection 移除连接
func (cm *ConnectionManager) RemoveConnection(sourceIP, destIP net.IP, protocol uint8) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	key := fmt.Sprintf("%s:%s:%d", sourceIP.String(), destIP.String(), protocol)
	delete(cm.connections, key)
}

// GetAllConnections 获取所有连接
func (cm *ConnectionManager) GetAllConnections() []*ConnectionMetadata {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	connections := make([]*ConnectionMetadata, 0, len(cm.connections))
	for _, conn := range cm.connections {
		connections = append(connections, conn)
	}
	return connections
}
