package device

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// handleTUNData 处理TUN设备数据
func (d *Device) handleTUNData() {
	defer d.wg.Done()

	buffers := make([][]byte, 1)
	sizes := make([]int, 1)
	buffers[0] = make([]byte, 1500) // MTU大小

	for {
		select {
		case <-d.stopChan:
			return
		default:
			n, err := d.tunDevice.Read(buffers, sizes, 0)
			if err != nil || n == 0 {
				continue
			}

			// 处理从TUN设备读取的数据
			// 这里可以根据目标IP查找对应的对端连接并转发
			d.forwardTUNData(buffers[0][:sizes[0]])
		}
	}
}

// forwardTUNData 转发TUN数据到对应的对端
func (d *Device) forwardTUNData(data []byte) {
	// 这里需要解析IP包，根据目标IP查找对应的对端连接
	// 简化实现，暂时不处理具体的数据转发逻辑
}

// startListener 启动网络监听
func (d *Device) startListener() error {
	addr := fmt.Sprintf(":%d", d.config.Interface.ListenPort)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	d.listener = listener
	return nil
}

// handleNetworkConnections 处理网络连接
func (d *Device) handleNetworkConnections() {
	defer d.wg.Done()

	for {
		select {
		case <-d.stopChan:
			return
		default:
			conn, err := d.listener.Accept()
			if err != nil {
				continue
			}

			// 处理 TLS 连接
			go d.handleTLSConnection(conn)
		}
	}
}

// handleTLSConnection 处理 TLS 连接
func (d *Device) handleTLSConnection(conn net.Conn) {
	defer conn.Close()

	// 创建 TLS 连接
	tlsConn := tls.Server(conn, d.tlsConfig)
	defer tlsConn.Close()

	// TLS握手
	if err := tlsConn.Handshake(); err != nil {
		return
	}

	// 验证客户端证书
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return
	}

	// 从证书中提取公钥信息
	cert := state.PeerCertificates[0]
	peerKey := cert.Subject.CommonName

	// 自定义握手协议
	_, err := d.performCustomHandshake(tlsConn)
	if err != nil {
		return
	}
	// Start-Process powershell -Verb runAs
	// 更新对端连接信息
	d.updatePeerConnection(peerKey, tlsConn)
}

// performCustomHandshake 执行自定义握手协议
func (d *Device) performCustomHandshake(tlsConn *tls.Conn) ([]byte, error) {
	// 设置读取超时
	tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer tlsConn.SetReadDeadline(time.Time{})

	// 1. 接收客户端发送的32字节ID
	clientID := make([]byte, 32)
	n, err := tlsConn.Read(clientID)
	if err != nil {
		return nil, fmt.Errorf("读取客户端ID失败: %v", err)
	}
	if n != 32 {
		return nil, fmt.Errorf("客户端ID长度不正确，期望32字节，实际%d字节", n)
	}

	// 2. 生成服务器ID（这里使用配置中的UniqueID作为服务器ID）
	serverID := []byte(d.config.Interface.UniqueID)
	if len(serverID) > 32 {
		serverID = serverID[:32] // 截断到32字节
	} else if len(serverID) < 32 {
		// 如果不足32字节，用0填充
		padded := make([]byte, 32)
		copy(padded, serverID)
		serverID = padded
	}

	// 3. 发送服务器ID给客户端
	if _, err := tlsConn.Write(serverID); err != nil {
		return nil, fmt.Errorf("发送服务器ID失败: %v", err)
	}

	fmt.Printf("握手完成 - 客户端ID: %x, 服务器ID: %x\n", clientID, serverID)
	return clientID, nil
}

// updatePeerConnection 更新对端连接信息
func (d *Device) updatePeerConnection(peerKey string, conn *tls.Conn) {
	d.connMutex.Lock()
	defer d.connMutex.Unlock()

	// 保存TLS连接
	d.connections[peerKey] = conn
}

// updatePeerDisconnection 更新对端断开连接状态
func (d *Device) updatePeerDisconnection(peerKey string) {
	d.indexMutex.Lock()
	d.connMutex.Lock()
	defer d.indexMutex.Unlock()
	defer d.connMutex.Unlock()

	// 移除 TLS 连接
	if conn, exists := d.connections[peerKey]; exists {
		conn.Close()
		delete(d.connections, peerKey)
	}
}
