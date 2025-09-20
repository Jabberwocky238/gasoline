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
			// 添加超时机制，避免无限阻塞
			n, err := d.tun.Read(buffers, sizes, 0)
			if err != nil {
				// 其他错误继续处理
				continue
			}
			if n == 0 {
				continue
			}
			// 处理从TUN设备读取的数据
			d.HandleOutbound(buffers[0][:sizes[0]])
		}
	}
}

// startListener 启动网络监听
func (d *Device) startListener() error {
	addr := fmt.Sprintf(":%d", d.config.Interface.ListenPort)

	fmt.Printf("启动服务器监听: %s\n", addr)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	d.listener = listener
	fmt.Printf("服务器监听启动成功: %s\n", addr)
	return nil
}

// connectToPeer 主动连接到对端
func (d *Device) connectToPeer(peer *PeerInfo) error {
	if peer.Endpoint == nil {
		return fmt.Errorf("对端没有endpoint")
	}

	fmt.Printf("尝试连接到对端: %s (%s)\n", peer.UniqueID[:8], peer.Endpoint.String())

	// 建立TCP连接
	conn, err := net.Dial("tcp", peer.Endpoint.String())
	if err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}

	fmt.Printf("TCP连接建立成功: %s\n", peer.Endpoint.String())

	// 创建客户端TLS配置
	clientTLSConfig := &tls.Config{
		ClientAuth:         tls.NoClientCert, // 不需要客户端证书
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,        // 跳过证书验证，用于测试
		ServerName:         "localhost", // 设置ServerName
	}

	// 创建TLS连接
	tlsConn := tls.Client(conn, clientTLSConfig)

	// TLS握手
	fmt.Printf("开始TLS握手: %s\n", peer.Endpoint.String())
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return fmt.Errorf("TLS握手失败: %v", err)
	}
	fmt.Printf("TLS握手成功: %s\n", peer.Endpoint.String())

	// 执行自定义握手协议
	fmt.Printf("开始自定义握手: %s\n", peer.Endpoint.String())
	_, err = d.performClientHandshake(tlsConn)
	if err != nil {
		tlsConn.Close()
		return fmt.Errorf("客户端握手失败: %v", err)
	}
	fmt.Printf("自定义握手成功: %s\n", peer.Endpoint.String())

	// 更新对端连接信息
	d.updatePeerConnection(peer.UniqueID, tlsConn)

	// 开始处理协议消息（在单独的协程中）
	go d.handleProtocolMessages(tlsConn, peer.UniqueID)

	fmt.Printf("成功连接到对端: %s\n", peer.UniqueID[:8])
	return nil
}

// performClientHandshake 执行客户端握手协议
func (d *Device) performClientHandshake(tlsConn *tls.Conn) ([]byte, error) {
	// 设置读取超时
	tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer tlsConn.SetReadDeadline(time.Time{})

	// 1. 发送客户端ID（使用配置中的UniqueID）
	clientID := []byte(d.config.Interface.UniqueID)
	if len(clientID) > 32 {
		clientID = clientID[:32] // 截断到32字节
	} else if len(clientID) < 32 {
		// 如果不足32字节，用0填充
		padded := make([]byte, 32)
		copy(padded, clientID)
		clientID = padded
	}

	// 发送客户端ID
	if _, err := tlsConn.Write(clientID); err != nil {
		return nil, fmt.Errorf("发送客户端ID失败: %v", err)
	}

	// 2. 接收服务器ID
	serverID := make([]byte, 32)
	n, err := tlsConn.Read(serverID)
	if err != nil {
		return nil, fmt.Errorf("读取服务器ID失败: %v", err)
	}
	if n != 32 {
		return nil, fmt.Errorf("服务器ID长度不正确，期望32字节，实际%d字节", n)
	}

	return serverID, nil
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

	fmt.Printf("收到新的客户端连接: %s\n", conn.RemoteAddr().String())

	// 创建 TLS 连接
	tlsConn := tls.Server(conn, d.tlsConfig)
	defer tlsConn.Close()

	// TLS握手
	fmt.Printf("开始服务器TLS握手: %s\n", conn.RemoteAddr().String())
	if err := tlsConn.Handshake(); err != nil {
		fmt.Printf("服务器TLS握手失败: %v\n", err)
		return
	}
	fmt.Printf("服务器TLS握手成功: %s\n", conn.RemoteAddr().String())

	// 自定义握手协议
	fmt.Printf("开始服务器自定义握手: %s\n", conn.RemoteAddr().String())
	clientID, err := d.performCustomHandshake(tlsConn)
	if err != nil {
		fmt.Printf("服务器自定义握手失败: %v\n", err)
		return
	}
	fmt.Printf("服务器自定义握手成功: %s\n", conn.RemoteAddr().String())

	// 将客户端ID转换为字符串作为peerKey
	peerKey := string(clientID)
	fmt.Printf("客户端ID: %s\n", peerKey[:8])

	// 更新对端连接信息
	d.updatePeerConnection(peerKey, tlsConn)

	fmt.Printf("客户端连接建立成功: %s\n", peerKey[:8])

	// 开始处理协议消息
	d.handleProtocolMessages(tlsConn, peerKey)
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

	return clientID, nil
}

// updatePeerConnection 更新对端连接信息
func (d *Device) updatePeerConnection(peerKey string, conn *tls.Conn) {
	d.connMutex.Lock()
	defer d.connMutex.Unlock()

	// 保存TLS连接
	d.connections[peerKey] = conn
}

// handleProtocolMessages 处理协议消息
func (d *Device) handleProtocolMessages(tlsConn *tls.Conn, peerKey string) {
	defer tlsConn.Close()

	// 借鉴frp的实现方式，使用更大的缓冲区
	buffer := make([]byte, 4096) // 4KB缓冲区，支持MTU大小的数据包
	for {
		select {
		case <-d.stopChan:
			return
		default:
			// 设置读取超时
			tlsConn.SetReadDeadline(time.Now().Add(30 * time.Second))

			// 先读取32字节头部
			header := make([]byte, 32)
			n, err := tlsConn.Read(header)
			if err != nil {
				// 连接断开，更新对端状态
				d.updatePeerDisconnection(peerKey)
				return
			}

			if n != 32 {
				continue
			}

			// 解析头部获取数据长度
			var tempMsg ProtocolMessage
			if err := tempMsg.Deserialize(header); err != nil {
				continue
			}

			// 读取完整消息
			totalLength := 32 + int(tempMsg.DataLength)
			if totalLength > len(buffer) {
				continue
			}

			// 复制头部到完整缓冲区
			copy(buffer, header)

			// 读取数据部分
			if tempMsg.DataLength > 0 {
				dataPart := buffer[32:totalLength]
				n, err := tlsConn.Read(dataPart)
				if err != nil || n != int(tempMsg.DataLength) {
					continue
				}
			}

			// 解析完整协议消息
			var msg ProtocolMessage
			if err := msg.Deserialize(buffer[:totalLength]); err != nil {
				continue
			}

			// 验证消息
			if !msg.IsValid() {
				continue
			}

			// 根据消息类型处理
			switch msg.Type {
			case Data:
				d.HandleInbound(&msg, tlsConn)
			default:
			}
		}
	}
}

// updatePeerDisconnection 更新对端断开连接状态
func (d *Device) updatePeerDisconnection(peerKey string) {
	d.indexMutex.Lock()
	d.connMutex.Lock()
	defer d.indexMutex.Unlock()
	defer d.connMutex.Unlock()

	// 移除 TLS 连接
	if conn, exists := d.connections[peerKey]; exists {
		fmt.Printf("客户端连接断开: %s\n", peerKey[:8])
		conn.Close()
		delete(d.connections, peerKey)
	}
}
