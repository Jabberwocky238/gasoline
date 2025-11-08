package device

import (
	"bytes"
	"net"
	"net/netip"
	"sync"

	// "time"
	"wwww/config"
	"wwww/transport"
	"wwww/transport/tcp"

	singTun "github.com/jabberwocky238/sing-tun"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type Device struct {
	cfg *config.Config
	tun singTun.Tun

	key struct {
		privateKey PrivateKey
		publicKey  PublicKey
	}

	peers      map[PublicKey]*Peer
	allowedips AllowedIPs

	listener struct {
		mu     sync.RWMutex
		server transport.TransportServer
	}
	endpoint struct {
		local net.IP
	}

	queue struct {
		outbound *genericQueue // 进入TUN的包
		routing  *genericQueue // 需要路由的包
	}

	log      *logrus.Logger
	debugger *Debugger
}

func NewDevice(cfg *config.Config, tun singTun.Tun) *Device {
	device := new(Device)
	device.log = logrus.New()
	device.log.SetLevel(logrus.DebugLevel)
	device.log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	device.debugger = NewDebugger(device)
	device.cfg = cfg
	device.tun = tun

	var privateKey PrivateKey
	if err := privateKey.FromBase64(device.cfg.Interface.PrivateKey); err != nil {
		device.log.Errorf("Failed to parse private key: %v", err)
		return nil
	}
	device.key.privateKey = privateKey
	device.key.publicKey = privateKey.PublicKey()

	prefix, err := netip.ParsePrefix(device.cfg.Interface.Address)
	if err != nil {
		device.log.Errorf("Failed to parse interface address: %v", err)
		return nil
	}
	localIp := prefix.Addr().AsSlice()
	device.endpoint.local = localIp
	device.log.Debugf("Device local IP %s", net.IP(localIp).String())

	device.peers = make(map[PublicKey]*Peer)
	for _, peerConfig := range device.cfg.Peers {
		peer, err := device.NewPeer(&peerConfig)
		if err != nil {
			device.log.Errorf("Failed to create peer: %v", err)
			continue
		}
		device.peers[peer.key.publicKey] = peer
		device.allowedips.Insert(peer.allowedIPs, peer)
	}

	return device
}

func (device *Device) Start() error {
	device.log.Debugf("Starting device")
	err := device.tun.Start()
	if err != nil {
		device.log.Errorf("Failed to start tun: %v", err)
		return err
	}
	device.debugger.Start()
	device.queue.outbound = newGenericQueue()
	device.queue.routing = newGenericQueue()

	for _, peer := range device.peers {
		err := peer.Start()
		if err != nil {
			device.log.Errorf("Failed to start peer %s: %v", peer.endpoint.local.String(), err)
			continue
		}
	}

	if device.cfg.Interface.ListenPort > 0 {
		go device.RoutineListenPort()
	}

	go device.RoutineRoutingPackets()
	go device.RoutineReadFromTUN()
	go device.RoutineWriteToTUN()
	// go device.RoutineBoardcast()

	return nil
}

func (device *Device) Close() {
	device.log.Debugf("Closing device")
	device.queue.outbound.wg.Done()
	device.queue.routing.wg.Done()
}

func (device *Device) RoutineListenPort() error {
	defer func() {
		device.log.Debugf("Routine: listen port - stopped")
	}()
	device.log.Debugf("Routine: listen port - started")

	host := "0.0.0.0"
	port := device.cfg.Interface.ListenPort

	server := tcp.NewTCPServer()
	err := server.Listen(host, port)
	if err != nil {
		device.log.Errorf("Failed to listen on port %d: %v", port, err)
		return err
	}

	device.listener.mu.Lock()
	device.listener.server = server
	device.listener.mu.Unlock()
	defer server.Close()

	for {
		conn, err := server.Accept()
		if err != nil {
			device.log.Errorf("Failed to accept connection: %v", err)
			continue
		}
		device.log.Debugf("Accepted connection from %s", conn.RemoteAddr().String())
		go func() {
			handshake := NewHandshake(conn, device, nil)
			publicKey, err := handshake.ReceiveHandshake()
			if err != nil {
				device.log.Errorf("Failed to receive handshake: %v", err)
				return
			}
			peer := device.peers[*publicKey]
			if peer == nil {
				device.log.Errorf("Peer not found for public key %s", publicKey)
				return
			}
			peer.conn.mu.Lock()
			peer.conn.conn = conn
			peer.conn.handshake = handshake
			peer.conn.isConnected = true
			peer.conn.mu.Unlock()

			device.log.Debugf("Connected to peer %s", peer.endpoint.local.String())
			go peer.RoutineSequentialSender()
			go peer.RoutineSequentialReceiver()
		}()
	}
}

// func (device *Device) RoutineBoardcast() error {
// 	defer func() {
// 		device.log.Debugf("Routine: boardcast - stopped")
// 	}()
// 	device.log.Debugf("Routine: boardcast - started")

// 	for {
// 		// 对所有peer进行Boardcast
// 		for _, peer := range device.peers {
// 			if !peer.conn.isConnected {
// 				continue
// 			}
// 			packet := manualPacket(device.endpoint.local, peer.endpoint.local)
// 			if packet == nil {
// 				device.log.Errorf("Failed to create packet for peer %s", peer.endpoint.local.String())
// 				continue
// 			}
// 			// 发送到peer的inbound队列，通过TCP发送给对端
// 			// device.log.Debugf("Sending packet to queue for peer %s, length: %d", peer.endpoint.local.String(), len(packet))
// 			peer.queue.inbound.queue <- packet
// 			// device.log.Debugf("Boardcast packet to peer %s, queue length: %d", peer.endpoint.local.String(), len(peer.queue.inbound.queue))
// 		}

// 		time.Sleep(3 * time.Second)
// 	}
// }

var (
	routingLenPeak = 0
)

func (device *Device) RoutineRoutingPackets() {
	defer func() {
		device.log.Debugf("Routine: routing packets - stopped")
	}()

	device.log.Debugf("Routine: routing packets - started")

	for packet := range device.queue.routing.c {
		// routingLenPeak = max(routingLenPeak, len(device.queue.routing.queue))
		// device.log.Debugf("queue length: %d, peak length: %d", len(device.queue.routing.queue), routingLenPeak)
		ipVersion := packet[0] >> 4
		length := len(packet)

		// lookup peer
		var peer *Peer
		var dst []byte
		switch ipVersion {
		case 4:
			if length < ipv4.HeaderLen {
				continue
			}
			device.debugger.LogPacket(packet, 4)
			dst = packet[IPv4offsetDst : IPv4offsetDst+net.IPv4len]
		case 6:
			if length < ipv6.HeaderLen {
				continue
			}
			device.debugger.LogPacket(packet, 6)
			dst = packet[IPv6offsetDst : IPv6offsetDst+net.IPv6len]
		default:
			device.log.Debugf("Received packet with unknown IP version")
			continue
		}
		// 判断接收者是不是自己
		if bytes.Equal(dst, device.endpoint.local) {
			device.queue.outbound.c <- packet
			continue
		}
		// 查找peer
		peer = device.allowedips.Lookup(dst)
		if peer == nil {
			// device.log.Errorf("Peer not found for IP %s", net.IP(dst).String())
			continue
		}
		peer.queue.inbound.c <- packet
	}
}
