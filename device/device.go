package device

import (
	"net"
	"net/netip"
	"sync"
	"time"
	"wwww/config"

	singTun "github.com/jabberwocky238/sing-tun"
	"github.com/sirupsen/logrus"
)

type genericQueue struct {
	queue chan []byte
	wg    sync.WaitGroup
}

func newGenericQueue() *genericQueue {
	q := &genericQueue{
		queue: make(chan []byte, 1024),
		wg:    sync.WaitGroup{},
	}
	q.wg.Add(1)
	go func() {
		q.wg.Wait()
		close(q.queue)
	}()
	return q
}

type Device struct {
	cfg *config.Config
	tun singTun.Tun

	peers map[PublicKey]*Peer

	key struct {
		privateKey PrivateKey
		publicKey  PublicKey
	}

	allowedips AllowedIPs

	endpoint struct {
		local net.IP
	}

	queue struct {
		inbound  *genericQueue
		outbound *genericQueue
	}

	log *logrus.Logger
}

func NewDevice(cfg *config.Config, tun singTun.Tun) *Device {
	device := new(Device)
	device.log = logrus.New()
	device.log.SetLevel(logrus.DebugLevel)
	device.log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

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
	device.queue.inbound = newGenericQueue()
	device.queue.outbound = newGenericQueue()

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

	go device.RoutineReadFromTUN()
	go device.RoutineWriteToTUN()
	go device.RoutineBoardcast()

	return nil
}

func (device *Device) Close() {
	device.log.Debugf("Closing device")
	device.queue.inbound.wg.Done()
	device.queue.outbound.wg.Done()
}

func (device *Device) RoutineListenPort() error {
	defer func() {
		device.log.Debugf("Routine: listen port - stopped")
	}()
	device.log.Debugf("Routine: listen port - started")

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: device.cfg.Interface.ListenPort,
	})
	if err != nil {
		device.log.Errorf("Failed to listen on port %d: %v", device.cfg.Interface.ListenPort, err)
		return err
	}

	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			device.log.Errorf("Failed to accept connection: %v", err)
			continue
		}
		device.log.Debugf("Accepted connection from %s", conn.RemoteAddr().String())
		go func() {
			var buf = make([]byte, net.IPv4len)
			n, err := conn.Read(buf)
			if err != nil {
				device.log.Errorf("Failed to read from connection: %v", err)
				return
			}
			if n == 0 {
				return
			}
			ciphertext := buf[:n]
			plaintext := Decrypt(ciphertext, device.key.privateKey)
			targetIp := net.IP(plaintext)
			peer := device.allowedips.Lookup(targetIp)
			if peer == nil {
				device.log.Errorf("Peer not found for IP %s", targetIp.String())
				return
			}
			peer.conn.Lock()
			peer.conn.tcp = conn.(*net.TCPConn)
			peer.conn.Unlock()
			peer.isConnected = true

			device.log.Debugf("Connected to peer %s", peer.endpoint.local.String())
			go peer.RoutineSequentialSender()
			go peer.RoutineSequentialReceiver()
		}()
	}
}

func (device *Device) RoutineBoardcast() error {
	defer func() {
		device.log.Debugf("Routine: boardcast - stopped")
	}()
	device.log.Debugf("Routine: boardcast - started")

	for {
		// 对所有peer进行Boardcast
		for _, peer := range device.peers {
			if !peer.isConnected {
				continue
			}
			packet := manualPacket(device.endpoint.local, peer.endpoint.local)
			if packet == nil {
				device.log.Errorf("Failed to create packet for peer %s", peer.endpoint.local.String())
				continue
			}
			// 发送到peer的inbound队列，通过TCP发送给对端
			device.log.Debugf("Sending packet to queue for peer %s, length: %d", peer.endpoint.local.String(), len(packet))
			peer.queue.inbound.queue <- packet
			device.log.Debugf("Boardcast packet to peer %s, queue length: %d", peer.endpoint.local.String(), len(peer.queue.inbound.queue))
			// device.log.Debugf("Boardcast packet to peer %s, queue length: %d", peer.endpoint.local.String(), len(peer.queue.inbound.queue))
		}

		time.Sleep(3 * time.Second)
	}
}
