package device

import (
	"container/list"
	"net"
	"net/netip"
	"sync"
	"time"
	"wwww/config"
	"wwww/transport"
	"wwww/transport/tcp"
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
		mu          sync.RWMutex
		handshake   *Handshake
		conn        transport.TransportConn
		isConnected bool
	}

	queue struct {
		inbound *genericQueue
	}

	//legacy
	trieEntries list.List
}

func (d *Device) NewPeer(cfg *config.Peer) (*Peer, error) {
	peer := new(Peer)

	// key
	var publicKey PublicKey
	if err := publicKey.FromBase64(cfg.PublicKey); err != nil {
		return nil, err
	}
	peer.key.publicKey = publicKey

	// transport client
	peer.conn.mu.Lock()
	peer.conn.handshake = nil
	peer.conn.isConnected = false
	peer.conn.mu.Unlock()

	// endpoint
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
	return peer, nil
}

func (p *Peer) Start() error {
	p.queue.inbound = newGenericQueue()
	if p.endpoint.remote != nil {
		p.device.log.Debugf("Start connecting to peer endpoint %s", p.endpoint.remote.String())
		// tcp connection
		p.conn.mu.Lock()

		// 添加重试机制
		var conn transport.TransportConn
		var err error
		var client transport.TransportClient = tcp.NewTCPClient()

		maxRetries := 3
		for i := 0; i < maxRetries; i++ {
			p.device.log.Debugf("Attempting connection %d/%d to %s", i+1, maxRetries, p.endpoint.remote.String())
			conn, err = client.Dial(p.endpoint.remote.String())
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
			p.conn.mu.Unlock()
			return err
		}

		// p.device.log.Debugf("Successfully connected to %s", p.endpoint.remote.String())
		handshake := NewHandshake(conn, p.device, p)
		err = handshake.SendHandshake()
		if err != nil {
			p.device.log.Errorf("Failed to send handshake to peer endpoint %s: %v", p.endpoint.remote.String(), err)
			p.conn.mu.Unlock()
			return err
		}
		p.conn.handshake = handshake
		p.conn.conn = conn
		p.conn.isConnected = true
		p.conn.mu.Unlock()
		p.device.log.Debugf("Connected to peer endpoint %s", p.endpoint.remote.String())

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

	for packet := range p.queue.inbound.queue {
		// p.device.log.Debugf("Sending packet to peer %s, length: %d", p.endpoint.local.String(), len(packet))
		_, err := p.conn.conn.Write(packet)
		if err != nil {
			p.device.log.Errorf("Failed to send packet: %v", err)
			p.conn.conn.Close()
			p.conn.conn = nil
			p.conn.isConnected = false
			return
		}
		// p.device.log.Debugf("Successfully sent packet to peer %s", p.endpoint.local.String())
	}
}

func (p *Peer) RoutineSequentialReceiver() {
	defer func() {
		p.device.log.Debugf("Routine: sequential receiver - stopped")
	}()
	p.device.log.Debugf("Routine: sequential receiver - started")

	packet := make([]byte, 1600)

	for {
		n, err := p.conn.conn.Read(packet)
		if err != nil {
			p.device.log.Errorf("Failed to receive packet: %v", err)
			return
		}
		if n == 0 {
			p.device.log.Debugf("Received packet with length 0 from peer %s", p.endpoint.local.String())
			continue
		}
		// p.device.log.Debugf("Received packet from peer %s, length: %d, sending to outbound queue", p.endpoint.local.String(), n)
		p.device.queue.routing.queue <- packet[:n]
	}
}
