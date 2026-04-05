package device

import (
	"container/list"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/jabberwocky238/gasoline/config"
	"github.com/jabberwocky238/gasoline/transport"
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
		client      transport.TransportClient
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
	var err error
	var endpoint netip.AddrPort
	var publicKey PublicKey

	// key
	if err := publicKey.FromBase64(cfg.PublicKey); err != nil {
		return nil, err
	}
	peer.key.publicKey = publicKey

	// transport client
	peer.conn.mu.Lock()
	peer.conn.client, err = config.FromConfigClient(d.ctx, d.cfg.Transports, cfg.TransportID)
	if err != nil {
		if peer.conn.client == nil {
			return nil, err
		}
		log.Warnf("Failed to create client: %v", err)
	}
	peer.conn.handshake = nil
	peer.conn.isConnected = false
	peer.conn.mu.Unlock()

	// endpoint

	if cfg.Endpoint != "" {
		endpoint, err = netip.ParseAddrPort(cfg.Endpoint)
		if err != nil {
			return nil, err
		}
		peer.endpoint.remote = &endpoint
		log.Debugf("New peer endpoint %s", endpoint.String())
	}
	allowedIPs, err := netip.ParsePrefix(cfg.AllowedIPs)
	if err != nil {
		return nil, err
	}
	localIp := allowedIPs.Addr().AsSlice()
	log.Debugf("New peer local IP %s", net.IP(localIp).String())
	peer.endpoint.local = localIp
	peer.allowedIPs = allowedIPs
	peer.device = d
	return peer, nil
}

func (p *Peer) Start() error {
	p.queue.inbound = newGenericQueue()
	if p.endpoint.remote != nil {
		log.Debugf("Start connecting to peer endpoint %s", p.endpoint.remote.String())
		// tcp connection
		p.conn.mu.Lock()

		// 添加重试机制
		var conn transport.TransportConn
		var err error

		maxRetries := 3
		for i := 0; i < maxRetries; i++ {
			log.Debugf("Attempting connection %d/%d to %s", i+1, maxRetries, p.endpoint.remote.String())
			conn, err = p.conn.client.Dial(p.endpoint.remote.String())
			if err == nil {
				break
			}
			log.Warnf("Connection attempt %d failed: %v", i+1, err)
			if i < maxRetries-1 {
				time.Sleep(2 * time.Second) // 重试前等待2秒
			}
		}

		if err != nil {
			log.Errorf("Failed to connect to peer endpoint %s after %d attempts: %v", p.endpoint.remote.String(), maxRetries, err)
			p.conn.mu.Unlock()
			return err
		}

		// p.device.log.Debugf("Successfully connected to %s", p.endpoint.remote.String())
		handshake := NewHandshake(conn, p.device, p)
		err = handshake.SendHandshake()
		if err != nil {
			log.Errorf("Failed to send handshake to peer endpoint %s: %v", p.endpoint.remote.String(), err)
			p.conn.mu.Unlock()
			return err
		}
		p.conn.handshake = handshake
		p.conn.conn = conn
		p.conn.isConnected = true
		p.conn.mu.Unlock()
		log.Debugf("Connected to peer endpoint %s", p.endpoint.remote.String())

		go p.RoutineSequentialSender()
		go p.RoutineSequentialReceiver()
	}
	return nil
}

func (p *Peer) attachConnection(conn transport.TransportConn, handshake *Handshake) {
	p.conn.mu.Lock()
	defer p.conn.mu.Unlock()
	p.conn.conn = conn
	p.conn.handshake = handshake
	p.conn.isConnected = true
}

func (p *Peer) Close() error {
	return nil
}

func (p *Peer) RoutineSequentialSender() {
	log.Debugf("Routine: sequential sender - started")
	defer func() {
		log.Debugf("Routine: sequential sender - stopped")
	}()

	for pb := range p.queue.inbound.c {
		_, err := p.conn.conn.Write(pb.Message())
		p.device.pools.PutPacketBuffer(pb)
		if err != nil {
			log.Errorf("Failed to send packet: %v", err)
			return
		}
	}
}

func (p *Peer) RoutineSequentialReceiver() {
	defer func() {
		log.Debugf("Routine: sequential receiver - stopped")
	}()
	log.Debugf("Routine: sequential receiver - started")

	var (
		buf          = make([]byte, 65535) // 接收缓冲，存放未解析的数据
		bufStart int = 0                   // 未解析数据起始偏移
		bufEnd   int = 0                   // 未解析数据结束偏移（开区间）
	)

	for {
		// 若缓冲末尾空间不足，进行压缩把未解析数据移到起始处
		if bufEnd == len(buf) && bufStart > 0 {
			copy(buf[0:], buf[bufStart:bufEnd])
			bufEnd -= bufStart
			bufStart = 0
		}

		// 读取到缓冲末尾的剩余空间
		n, err := p.conn.conn.Read(buf[bufEnd:])
		if err != nil {
			log.Errorf("Failed to receive packet: %v", err)
			return
		}
		if n == 0 {
			log.Debugf("Received packet with length 0 from peer %s", p.endpoint.local.String())
			continue
		}
		bufEnd += n

		// 循环解包：尽可能多地从缓冲区解析完整帧
		for {
			// 至少需要2字节长度
			if bufEnd-bufStart < MessageHeaderSize {
				break
			}
			frameLen := int(binary.LittleEndian.Uint16(buf[bufStart : bufStart+MessageHeaderSize]))

			// 合法性检查
			if frameLen < 0 || frameLen > len(buf)-2 {
				log.Errorf("Invalid frame length: %d", frameLen)
				return
			}
			// 半包：等待更多数据
			if bufEnd-bufStart < MessageHeaderSize+frameLen {
				break
			}
			// 完整包：解出头部+负载，避免后续缓冲移动影响
			segmentStart := bufStart + MessageHeaderSize
			segmentEnd := bufStart + MessageHeaderSize + frameLen
			pb := p.device.pools.GetPacketBuffer()
			pb.SetPacket(buf[segmentStart:segmentEnd])
			p.device.queue.routing.c <- pb
			// 前进指针
			bufStart = segmentEnd
			// 如果完全消耗，重置索引
			if bufStart == bufEnd {
				bufStart = 0
				bufEnd = 0
				break
			}
			// 若已消耗一部分，且剩余数据不多，可适度压缩以腾出空间
			if bufStart > 0 && (len(buf)-bufEnd) < 1600 {
				copy(buf[0:], buf[bufStart:bufEnd])
				bufEnd -= bufStart
				bufStart = 0
			}
		}
	}
}
