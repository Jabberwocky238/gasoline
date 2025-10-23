package device

import (
	"container/list"
	"net"
	"net/netip"
	"sync"
	"time"
	"wwww/config"
)

type Peer struct {
	allowedIPs netip.Prefix

	device *Device

	key struct {
		publicKey PublicKey
	}

	endpoint struct {
		local  net.IP
		remote *netip.AddrPort
	}

	conn struct {
		sync.RWMutex
		tcp *net.TCPConn
	}

	queue struct {
		// outbound *genericQueue  // 发送给peer的包
		inbound *genericQueue // 从TUN读取的包，需要发送给其他peer
	}

	//legacy
	trieEntries list.List
	isConnected bool
}

func (d *Device) NewPeer(cfg *config.Peer) (*Peer, error) {
	peer := new(Peer)

	var publicKey PublicKey
	if err := publicKey.FromBase64(cfg.PublicKey); err != nil {
		return nil, err
	}
	peer.key.publicKey = publicKey

	var endpoint netip.AddrPort
	var err error
	if cfg.Endpoint != "" {
		endpoint, err = netip.ParseAddrPort(cfg.Endpoint)
		if err != nil {
			return nil, err
		}
		peer.endpoint.remote = &endpoint
		d.log.Debugf("New peer endpoint %s", endpoint.String())
	}
	allowedIPs, err := netip.ParsePrefix(cfg.AllowedIPs)
	if err != nil {
		return nil, err
	}
	localIp := allowedIPs.Addr().AsSlice()
	d.log.Debugf("New peer local IP %s", net.IP(localIp).String())
	peer.endpoint.local = localIp
	peer.allowedIPs = allowedIPs
	peer.device = d
	peer.isConnected = false
	return peer, nil
}

func (p *Peer) Start() error {
	p.queue.inbound = newGenericQueue()
	if p.endpoint.remote != nil {
		p.device.log.Debugf("Start connecting to peer endpoint %s", p.endpoint.remote.String())
		// tcp connection
		p.conn.Lock()

		// 添加重试机制
		var conn net.Conn
		var err error
		maxRetries := 3
		for i := 0; i < maxRetries; i++ {
			p.device.log.Debugf("Attempting connection %d/%d to %s", i+1, maxRetries, p.endpoint.remote.String())
			conn, err = net.DialTimeout("tcp", p.endpoint.remote.String(), 3*time.Second)
			if err == nil {
				break
			}
			p.device.log.Warnf("Connection attempt %d failed: %v", i+1, err)
			if i < maxRetries-1 {
				time.Sleep(2 * time.Second) // 重试前等待2秒
			}
		}

		if err != nil {
			p.device.log.Errorf("Failed to connect to peer endpoint %s after %d attempts: %v", p.endpoint.remote.String(), maxRetries, err)
			p.conn.Unlock()
			return err
		}

		// p.device.log.Debugf("Successfully connected to %s", p.endpoint.remote.String())

		var buf = make([]byte, net.IPv4len)
		plaintext := make([]byte, len(p.device.endpoint.local))
		copy(plaintext, p.device.endpoint.local)
		ciphertext := Encrypt(plaintext, p.device.key.publicKey)
		copy(buf, ciphertext)
		conn.Write(buf)

		p.conn.tcp = conn.(*net.TCPConn)
		p.conn.Unlock()
		p.device.log.Debugf("Connected to peer endpoint %s", p.endpoint.remote.String())
		p.isConnected = true

		go p.RoutineSequentialSender()
		go p.RoutineSequentialReceiver()
	}
	return nil
}

func (p *Peer) Close() error {
	// 不要立即关闭队列，让RoutineSequentialSender自然结束
	// p.queue.outbound.wg.Done()
	// p.queue.inbound.wg.Done()
	return nil
}

func (p *Peer) RoutineSequentialSender() {
	defer func() {
		p.device.log.Debugf("Routine: sequential sender - stopped")
	}()
	p.device.log.Debugf("Routine: sequential sender - started")

	for {
		select {
		case packet, ok := <-p.queue.inbound.queue:
			if !ok {
				p.device.log.Debugf("Queue closed, stopping sender")
				return
			}
			// p.device.log.Debugf("Sending packet to peer %s, length: %d", p.endpoint.local.String(), len(packet))

			ciphertext := Encrypt(packet, p.key.publicKey)

			_, err := p.conn.tcp.Write(ciphertext)
			if err != nil {
				p.device.log.Errorf("Failed to send packet: %v", err)
				p.conn.tcp.Close()
				p.conn.tcp = nil
				p.isConnected = false
				return
			}
			// p.device.log.Debugf("Successfully sent packet to peer %s", p.endpoint.local.String())
		}
	}
}

func (p *Peer) RoutineSequentialReceiver() {
	defer func() {
		p.device.log.Debugf("Routine: sequential receiver - stopped")
	}()
	p.device.log.Debugf("Routine: sequential receiver - started")

	packet := make([]byte, 1600)

	for {
		n, err := p.conn.tcp.Read(packet)
		if err != nil {
			p.device.log.Errorf("Failed to receive packet: %v", err)
			return
		}
		if n == 0 {
			p.device.log.Debugf("Received packet with length 0 from peer %s", p.endpoint.local.String())
			continue
		}
		ciphertext := packet[:n]
		plaintext := Decrypt(ciphertext, p.device.key.privateKey)
		p.device.log.Debugf("Received packet from peer %s, length: %d, sending to outbound queue", p.endpoint.local.String(), n)
		p.device.queue.outbound.queue <- plaintext
	}
}
