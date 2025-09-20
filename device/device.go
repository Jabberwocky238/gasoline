package device

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"wwww/config"
	"wwww/tun"
)

// PeerInfo 对端信息
type PeerInfo struct {
	UniqueID   string
	Ip         net.IP
	AllowedIPs net.IPNet
	Endpoint   net.Addr
}

// Device 设备结构体
type Device struct {
	// 配置信息
	config *config.Config

	// TUN 接口
	tunDevice tun.Device

	// 对端映射表 (公钥 -> PeerInfo)
	indexMap   map[string]*PeerInfo
	indexMutex sync.RWMutex

	// 对端 TLS 连接映射表 (公钥 -> TLS连接)
	connections map[string]*tls.Conn
	connMutex   sync.RWMutex

	// 网络监听
	listener  net.Listener
	tlsConfig *tls.Config

	// 控制通道
	stopChan chan struct{}
	wg       sync.WaitGroup

	// 连接管理器
	connectionManager *ConnectionManager
}

// NewDevice 创建新的设备实例
func NewDevice(cfg *config.Config) (*Device, error) {
	device := &Device{
		config:            cfg,
		indexMap:          make(map[string]*PeerInfo),
		connections:       make(map[string]*tls.Conn),
		stopChan:          make(chan struct{}),
		connectionManager: NewConnectionManager(),
	}

	// 初始化对端映射表
	device.indexMutex.Lock()
	defer device.indexMutex.Unlock()

	for _, peer := range device.config.Peers {
		ip, allowedIPs, err := net.ParseCIDR(peer.AllowedIPs)
		if err != nil {
			return nil, fmt.Errorf("解析允许IPs失败: %v", err)
		}
		var endpoint net.Addr
		if peer.Endpoint != "" {
			var err error
			endpoint, err = net.ResolveTCPAddr("tcp", peer.Endpoint)
			if err != nil {
				return nil, fmt.Errorf("解析端点失败: %v", err)
			}
		}
		device.indexMap[peer.UniqueID] = &PeerInfo{
			UniqueID:   peer.UniqueID,
			Ip:         ip,
			AllowedIPs: *allowedIPs,
			Endpoint:   endpoint,
		}
	}

	// 生成自签名证书
	cert, err := generateSelfSignedCert()
	if err != nil {
		return nil, fmt.Errorf("生成自签名证书失败: %v", err)
	}

	device.tlsConfig = &tls.Config{
		Certificates:       []tls.Certificate{cert},
		ClientAuth:         tls.NoClientCert, // 不需要客户端证书
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // 跳过证书验证，用于测试
	}

	// 初始化 TUN 设备
	if err := device.initializeTUN(); err != nil {
		return nil, fmt.Errorf("初始化 TUN 设备失败: %v", err)
	}

	return device, nil
}

// Start 启动设备
func (d *Device) Start() error {
	// 检查是否为服务器模式（有ListenPort）
	if d.config.Interface.ListenPort > 0 {
		// 启动网络监听
		if err := d.startListener(); err != nil {
			return fmt.Errorf("启动监听失败: %v", err)
		}

		// 启动处理协程
		d.wg.Add(2)
		go d.handleNetworkConnections()
		go d.handleTUNData()
	} else {
		// 客户端模式，启动TUN数据处理和主动连接
		d.wg.Add(1)
		go d.handleTUNData()

	}
	// 主动连接到有endpoint的peers
	go d.connectToPeers()

	return nil
}

// connectToPeers 连接到所有有endpoint的peers
func (d *Device) connectToPeers() {
	d.indexMutex.RLock()
	peers := make([]*PeerInfo, 0)
	for _, peer := range d.indexMap {
		// 只连接有endpoint的peers，且不是自己
		if peer.Endpoint != nil && peer.UniqueID != d.config.Interface.UniqueID {
			peers = append(peers, peer)
		}
	}
	d.indexMutex.RUnlock()

	if len(peers) == 0 {
		fmt.Println("没有需要连接的peers")
		return
	}

	fmt.Printf("发现 %d 个需要连接的peers\n", len(peers))

	// 连接到每个peer
	for _, peer := range peers {
		go func(p *PeerInfo) {
			for {
				select {
				case <-d.stopChan:
					return
				default:
					if err := d.connectToPeer(p); err != nil {
						fmt.Printf("连接到对端 %s 失败: %v，5秒后重试\n", p.UniqueID, err)
						time.Sleep(5 * time.Second)
						continue
					}
					// 连接成功，退出重试循环
					return
				}
			}
		}(peer)
	}
}

// Stop 停止设备
func (d *Device) Stop() error {
	close(d.stopChan)

	// 关闭所有 peer 连接
	d.connMutex.Lock()
	for peerKey, conn := range d.connections {
		conn.Close()
		delete(d.connections, peerKey)
	}
	d.connMutex.Unlock()

	// 关闭监听器
	if d.listener != nil {
		d.listener.Close()
	}

	// 关闭 TUN 设备
	if d.tunDevice != nil {
		d.tunDevice.Close()
	}

	// 等待所有协程结束
	d.wg.Wait()

	return nil
}

// findPeerByIP 根据IP地址查找对应的对端连接
func (d *Device) findPeerByIP(destIP net.IP) *tls.Conn {
	d.indexMutex.RLock()
	d.connMutex.RLock()
	defer d.indexMutex.RUnlock()
	defer d.connMutex.RUnlock()

	// 遍历所有对端，检查目的IP是否在允许的IP范围内
	for peerKey, peer := range d.indexMap {
		if peer.AllowedIPs.Contains(destIP) {
			if conn, exists := d.connections[peerKey]; exists {
				fmt.Printf("找到对端 %s，IP范围: %s\n", peerKey, peer.AllowedIPs.String())
				return conn
			}
		}
	}

	return nil
}

// generateSelfSignedCert 生成自签名证书
func generateSelfSignedCert() (tls.Certificate, error) {
	// 生成私钥
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	// 创建证书模板
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"WireGuard-like VPN"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // 1年有效期
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:    []string{"localhost"},
	}

	// 生成证书
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	// 创建TLS证书
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	return cert, nil
}
