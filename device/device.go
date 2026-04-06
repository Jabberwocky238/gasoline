package device

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/transport"

	singTun "github.com/sagernet/sing-tun"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type Device struct {
	ctx    context.Context
	cancel context.CancelFunc
	cfg    *config.Config
	tun    singTun.Tun

	key struct {
		privateKey PrivateKey
		publicKey  PublicKey
	}

	peers      map[PublicKey]*Peer
	allowedips AllowedIPs

	endpoint struct {
		local net.IP
	}

	listener transport.Listener

	queue struct {
		outbound *genericQueue // 进入TUN的包
		routing  *genericQueue // 需要路由的包
	}

	pools    *Pools
	debugger *Debugger
	watcher  *Watcher
}

func NewDevice(cfg *config.Config, tun singTun.Tun) *Device {
	device := &Device{
		cfg:   cfg,
		tun:   tun,
		pools: NewPool(),
	}
	device.ctx, device.cancel = context.WithCancel(context.Background())
	device.debugger = NewDebugger(device)

	if err := device.initialize(); err != nil {
		log.Errorf("Failed to initialize device: %v", err)
		device.cancel()
		return nil
	}

	return device
}

func (device *Device) Start() error {
	log.Debugf("Starting device")
	err := device.tun.Start()
	if err != nil {
		log.Errorf("Failed to start tun: %v", err)
		return err
	}

	go device.debugger.Start()
	device.queue.outbound = newGenericQueue()
	device.queue.routing = newGenericQueue()

	watcher, err := NewWatcher(device.ctx, ".gasoline")
	if err != nil {
		log.Errorf("Failed to initialize watcher: %v", err)
	} else {
		device.watcher = watcher
		go device.watcher.Start()
	}

	for _, peer := range device.peers {
		err := peer.Start()
		if err != nil {
			log.Errorf("Failed to start peer %s: %v", peer.endpoint.local.String(), err)
			continue
		}
	}

	if device.listener != nil {
		go device.RoutineListenPort()
	}

	go device.RoutineRoutingPackets()
	go device.RoutineReadFromTUN(0)
	go device.RoutineWriteToTUN()

	return nil
}

func (device *Device) Close() {
	log.Debugf("Closing device")
	if device.queue.outbound != nil {
		device.queue.outbound.wg.Done()
	}
	if device.queue.routing != nil {
		device.queue.routing.wg.Done()
	}
	if device.listener != nil {
		device.listener.Close()
	}
	if device.watcher != nil {
		device.watcher.Close()
	}
	device.cancel()
	device.tun.Close()
}

func (device *Device) RoutineListenPort() {
	defer log.Debugf("Routine: listen port - stopped")
	log.Debugf("Routine: listen port - started")

	for {
		conn, result, err := device.listener.Accept()
		if err != nil {
			select {
			case <-device.ctx.Done():
				return
			default:
				log.Errorf("Failed to accept connection: %v", err)
				continue
			}
		}
		go device.handleIncomingConnection(conn, result)
	}
}

func (device *Device) RoutineRoutingPackets() {
	defer log.Debugf("Routine: routing packets - stopped")
	log.Debugf("Routine: routing packets - started")

	var (
		ticker               = time.NewTicker(1 * time.Second)
		correctPacketCount   = 0
		incorrectPacketCount = 0
	)

	defer ticker.Stop()

	go func() {
		for range ticker.C {
			log.Debugf("Routine: routing packets - correct: %d, incorrect: %d", correctPacketCount, incorrectPacketCount)
		}
	}()

	for pb := range device.queue.routing.c {
		dst, err := packetDestination(pb)
		if err != nil {
			log.Debugf("Dropping packet during routing: %v", err)
			device.pools.PutPacketBuffer(pb)
			incorrectPacketCount++
			continue
		}

		correctPacketCount++
		if bytes.Equal(dst, device.endpoint.local) {
			device.queue.outbound.c <- pb
			continue
		}

		peer := device.allowedips.Lookup(dst)
		if peer == nil {
			device.pools.PutPacketBuffer(pb)
			incorrectPacketCount++
			continue
		}
		peer.queue.inbound.c <- pb
	}
}

func (device *Device) initialize() error {
	if err := device.initializeListener(); err != nil {
		return err
	}
	if err := device.initializeKeys(); err != nil {
		return err
	}
	if err := device.initializeLocalEndpoint(); err != nil {
		return err
	}
	device.initializePeers()
	return nil
}

func (device *Device) initializeListener() error {
	if device.cfg.Interface.ListenPort <= 0 {
		return nil
	}
	listener, err := NewDeviceListener(device.ctx, device.cfg)
	if err != nil {
		return err
	}
	device.listener = listener
	return nil
}

func (device *Device) initializeKeys() error {
	var privateKey PrivateKey
	if err := privateKey.FromBase64(device.cfg.Interface.PrivateKey); err != nil {
		return err
	}
	device.key.privateKey = privateKey
	device.key.publicKey = privateKey.PublicKey()
	return nil
}

func (device *Device) initializeLocalEndpoint() error {
	prefix, err := netip.ParsePrefix(device.cfg.Interface.Address)
	if err != nil {
		return err
	}
	localIP := prefix.Addr().AsSlice()
	device.endpoint.local = localIP
	log.Debugf("Device local IP %s", net.IP(localIP).String())
	return nil
}

func (device *Device) initializePeers() {
	device.peers = make(map[PublicKey]*Peer)
	for _, peerConfig := range device.cfg.Peers {
		peer, err := device.NewPeer(&peerConfig)
		if err != nil {
			log.Errorf("Failed to create peer: %v", err)
			continue
		}
		device.peers[peer.key.publicKey] = peer
		device.allowedips.Insert(peer.allowedIPs, peer)
	}
}

func (device *Device) handleIncomingConnection(conn transport.Conn, result *protocol.HandshakeResult) {
	log.Debugf("Handshake completed with client %x from %s", result.ClientID, conn.RemoteAddr())

	var peer *Peer
	for _, p := range device.peers {
		if p.clientID == result.ClientID {
			peer = p
			break
		}
	}
	if peer == nil {
		log.Errorf("No peer found for clientID %x", result.ClientID)
		conn.Close()
		return
	}

	peer.attachConnection(conn)
	log.Debugf("Connected to peer %s", peer.endpoint.local.String())
	go peer.RoutineSequentialSender()
	go peer.RoutineSequentialReceiver()
}

func packetDestination(pb *PacketBuffer) ([]byte, error) {
	switch pb.IpVersion() {
	case 4:
		if pb.length < ipv4.HeaderLen {
			return nil, fmt.Errorf("short IPv4 packet: %d", pb.length)
		}
		return pb.Packet()[IPv4offsetDst : IPv4offsetDst+net.IPv4len], nil
	case 6:
		if pb.length < ipv6.HeaderLen {
			return nil, fmt.Errorf("short IPv6 packet: %d", pb.length)
		}
		return pb.Packet()[IPv6offsetDst : IPv6offsetDst+net.IPv6len], nil
	default:
		return nil, fmt.Errorf("unknown IP version: %d", pb.IpVersion())
	}
}
