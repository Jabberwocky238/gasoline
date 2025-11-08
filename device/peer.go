package device

import (
	"bufio"
	"container/list"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"time"
	"wwww/config"
	"wwww/transport"
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
	peer.conn.client, err = NewClient(d.ctx, "tcp")
	if err != nil {
		return nil, err
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

		maxRetries := 3
		for i := 0; i < maxRetries; i++ {
			p.device.log.Debugf("Attempting connection %d/%d to %s", i+1, maxRetries, p.endpoint.remote.String())
			conn, err = p.conn.client.Dial(p.endpoint.remote.String())
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
	return nil
}

func (p *Peer) RoutineSequentialSender() {
	// 使用bufio.Writer来缓冲写入，减少系统调用，让TCP可以批量发送
	// 缓冲区大小设置为64KB，这样可以让TCP层累积多个数据包后一次性发送
	writer := bufio.NewWriterSize(p.conn.conn, 64*1024)

	// 使用ticker定期刷新缓冲区，避免数据包延迟太久
	flushTicker := time.NewTicker(10 * time.Millisecond)
	defer func() {
		flushTicker.Stop()
		// 确保退出时刷新缓冲区，避免丢失数据
		writer.Flush()
		p.device.log.Debugf("Routine: sequential sender - stopped")
	}()
	p.device.log.Debugf("Routine: sequential sender - started")

	for {
		select {
		case pb, ok := <-p.queue.inbound.c:
			if !ok {
				// channel已关闭，刷新缓冲区后退出
				writer.Flush()
				return
			}

			// 写入到缓冲writer，而不是直接写入连接
			_, err := writer.Write(pb.CopyMessage())
			p.device.pools.PutPacketBuffer(pb)
			if err != nil {
				p.device.log.Errorf("Failed to send packet: %v", err)
				return
			}

			// 如果缓冲区接近满，立即刷新以触发发送
			if writer.Buffered() > 32*1024 {
				if err := writer.Flush(); err != nil {
					p.device.log.Errorf("Failed to flush buffer: %v", err)
					return
				}
			}
		case <-flushTicker.C:
			// 定期刷新缓冲区，确保数据包不会延迟太久
			if writer.Buffered() > 0 {
				if err := writer.Flush(); err != nil {
					p.device.log.Errorf("Failed to flush buffer: %v", err)
					return
				}
			}
		}
	}
}

func (p *Peer) RoutineSequentialReceiver() {
	defer func() {
		p.device.log.Debugf("Routine: sequential receiver - stopped")
	}()
	p.device.log.Debugf("Routine: sequential receiver - started")

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
			p.device.log.Errorf("Failed to receive packet: %v", err)
			return
		}
		if n == 0 {
			p.device.log.Debugf("Received packet with length 0 from peer %s", p.endpoint.local.String())
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
				p.device.log.Errorf("Invalid frame length: %d", frameLen)
				return
			}
			// 半包：等待更多数据
			if bufEnd-bufStart < MessageHeaderSize+frameLen {
				break
			}
			// 完整包：解出头部+负载，避免后续缓冲移动影响
			segmentStart := bufStart + MessageHeaderSize
			segmentEnd := bufStart + MessageHeaderSize + frameLen
			segment := buf[segmentStart:segmentEnd]
			pb := p.device.pools.GetPacketBuffer()
			pb.Set(segment)
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
