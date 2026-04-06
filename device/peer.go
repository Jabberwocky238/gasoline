package device

import (
	"container/list"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/jabberwocky238/gasoline/config"
	"github.com/jabberwocky238/gasoline/transport"
)

type Peer struct {
	clientID   [16]byte
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
		dialer      transport.Dialer
		conn        transport.Conn
		isConnected bool
	}

	queue struct {
		inbound *genericQueue
	}

	// legacy
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

	// dialer
	peer.conn.mu.Lock()
	peer.conn.dialer, err = config.FromConfigDialer(d.ctx, d.cfg.Transports, cfg.TransportID)
	if err != nil {
		if peer.conn.dialer == nil {
			return nil, err
		}
		log.Warnf("Failed to create dialer: %v", err)
	}
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
	if p.endpoint.remote == nil {
		return nil
	}

	log.Debugf("Start connecting to peer endpoint %s", p.endpoint.remote.String())
	p.conn.mu.Lock()
	defer p.conn.mu.Unlock()

	var conn transport.Conn
	var err error

	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		log.Debugf("Attempting connection %d/%d to %s", i+1, maxRetries, p.endpoint.remote.String())
		conn, _, err = p.conn.dialer.Dial(p.endpoint.remote.String())
		if err == nil {
			break
		}
		log.Warnf("Connection attempt %d failed: %v", i+1, err)
		if i < maxRetries-1 {
			time.Sleep(2 * time.Second)
		}
	}

	if err != nil {
		log.Errorf("Failed to connect after %d attempts: %v", maxRetries, err)
		return err
	}

	p.conn.conn = conn
	p.conn.isConnected = true
	log.Debugf("Connected to peer endpoint %s", p.endpoint.remote.String())

	go p.RoutineSequentialSender()
	go p.RoutineSequentialReceiver()
	return nil
}

func (p *Peer) attachConnection(conn transport.Conn) {
	p.conn.mu.Lock()
	defer p.conn.mu.Unlock()
	p.conn.conn = conn
	p.conn.isConnected = true
}

func (p *Peer) Close() error {
	p.conn.mu.Lock()
	defer p.conn.mu.Unlock()
	if p.conn.conn != nil {
		p.conn.conn.Close()
	}
	p.conn.isConnected = false
	return nil
}

// RoutineSequentialSender reads packets from inbound queue and sends them via transport.
func (p *Peer) RoutineSequentialSender() {
	log.Debugf("Routine: sequential sender - started")
	defer log.Debugf("Routine: sequential sender - stopped")

	for pb := range p.queue.inbound.c {
		err := p.conn.conn.WritePacket(pb.Packet())
		p.device.pools.PutPacketBuffer(pb)
		if err != nil {
			log.Errorf("Failed to send packet: %v", err)
			return
		}
	}
}

// RoutineSequentialReceiver reads packets from transport and routes them.
// Transport handles framing — each ReadPacket returns one complete IP packet.
func (p *Peer) RoutineSequentialReceiver() {
	log.Debugf("Routine: sequential receiver - started")
	defer log.Debugf("Routine: sequential receiver - stopped")

	for {
		data, err := p.conn.conn.ReadPacket()
		if err != nil {
			log.Errorf("Failed to receive packet: %v", err)
			return
		}
		if len(data) == 0 {
			continue
		}

		pb := p.device.pools.GetPacketBuffer()
		pb.SetPacket(data)
		p.device.queue.routing.c <- pb
	}
}
