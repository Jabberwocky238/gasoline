package device

import (
	"crypto/tls"
	"fmt"
)

// HandleOutbound 处理从TUN设备读取的数据包（出站流量）
func (d *Device) HandleOutbound(data []byte) {
	// 解析IP头部获取连接信息
	ipHeader, err := ParseIPHeader(data)
	if err != nil {
		// 静默跳过无法解析的包（可能是IPv6或其他格式）
		fmt.Printf("无法解析IP头部: %v\n", err)
		return
	}

	// fmt.Printf("处理出站数据包: %s -> %s (协议: %d)\n",
	// 	ipHeader.SourceIP.String(), ipHeader.DestIP.String(), ipHeader.Protocol)

	// 首先检查目标IP是否在peers的AllowedIPs范围内
	if !d.IsIPInAllowedRange(ipHeader.DestIP) {
		// fmt.Printf("目标IP %s 不在允许范围内\n", ipHeader.DestIP.String())
		return
	}

	// 检查是否为广播或多播包
	if IsBroadcastOrMulticast(ipHeader.DestIP) {
		fmt.Printf("跳过广播/多播包: %s\n", ipHeader.DestIP.String())
		// 广播包暂时跳过，避免在没有对端时造成循环
		return
	}

	// 创建或更新连接元数据
	metadata := d.connectionManager.GetOrCreateConnection(
		ipHeader.SourceIP,
		ipHeader.DestIP,
		ipHeader.Protocol,
	)

	// 设置端口信息
	metadata.SourcePort = ipHeader.GetSourcePort(data)
	metadata.DestPort = ipHeader.GetDestPort(data)

	// 更新统计信息
	metadata.UpdateStats(0, uint64(len(data)))

	// 根据目标IP查找对应的对端连接
	targetConn := d.findPeerByIP(ipHeader.DestIP)
	if targetConn == nil {
		fmt.Printf("未找到目标IP %s 对应的对端连接\n", ipHeader.DestIP.String())
		return
	}

	fmt.Printf("找到对端连接，发送数据包到 %s\n", ipHeader.DestIP.String())
	// 发送到目标对端
	d.sendToPeer(targetConn, data)
}

// sendToPeer 发送数据到指定的对端连接
func (d *Device) sendToPeer(targetConn *tls.Conn, data []byte) error {
	// 创建协议消息
	msg := NewProtocolMessage(Data, nil, nil, data)

	// 序列化协议消息
	serializedData := msg.Serialize()

	// 发送到目标对端
	_, err := targetConn.Write(serializedData)
	if err != nil {
		return fmt.Errorf("发送数据到对端失败: %v", err)
	}

	return nil
}

// broadcastToAllPeers 将数据包广播给所有对端
func (d *Device) broadcastToAllPeers(data []byte) {
	d.connMutex.RLock()
	defer d.connMutex.RUnlock()

	fmt.Printf("广播数据包到 %d 个对端\n", len(d.connections))

	// 发送给所有已连接的对端
	for peerKey, conn := range d.connections {
		fmt.Printf("发送广播包到对端: %s\n", peerKey[:8])
		if err := d.sendToPeer(conn, data); err != nil {
			fmt.Printf("发送广播包到对端 %s 失败: %v\n", peerKey[:8], err)
		}
	}
}
