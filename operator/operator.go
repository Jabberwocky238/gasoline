package operator

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/jabberwocky238/gasoline/device"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/transport"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type Config struct {
	// Auth strategy for incoming handshakes
	Auth protocol.ServerAuthenticator
	// ConfigFunc generates SessionConfig for each client after auth
	ConfigFn protocol.ConfigFunc
	// Listener accepts transport connections
	Listener transport.Listener
}

// peerConn represents a connected client.
type peerConn struct {
	conn     transport.Conn
	clientID [16]byte
	ip       netip.Prefix // assigned IP
}

// Operator accepts client connections, decrypts packets, and routes them
// to the correct client by destination IP.
type Operator struct {
	mu     sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc

	cfg *Config

	// connected clients indexed by assigned IP → peerConn
	peers      map[netip.Addr]*peerConn
	allowedips device.AllowedIPs

	pools *device.Pools
}

func New(cfg *Config) *Operator {
	ctx, cancel := context.WithCancel(context.Background())
	return &Operator{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
		peers:  make(map[netip.Addr]*peerConn),
		pools:  device.NewPool(),
	}
}

// Start begins accepting client connections and routing packets.
func (o *Operator) Start() error {
	log.Infof("Operator listening on %s", o.cfg.Listener.Addr())
	go o.routineAccept()
	return nil
}

// routineAccept accepts new clients (handshake already done by transport layer).
func (o *Operator) routineAccept() {
	for {
		conn, result, err := o.cfg.Listener.Accept()
		if err != nil {
			select {
			case <-o.ctx.Done():
				return
			default:
				log.Errorf("Accept failed: %v", err)
				continue
			}
		}

		pc := &peerConn{
			conn:     conn,
			clientID: result.ClientID,
			ip:       result.Config.IPPrefix,
		}

		addr := result.Config.IPPrefix.Addr()
		o.mu.Lock()
		o.peers[addr] = pc
		o.mu.Unlock()

		log.Infof("Client %x connected, assigned %s from %s",
			result.ClientID, result.Config.IPPrefix, conn.RemoteAddr())

		// Start reading packets from this client
		go o.routineReadFromClient(pc)
	}
}

// routineReadFromClient reads packets from a client and routes them to the destination client.
func (o *Operator) routineReadFromClient(pc *peerConn) {
	defer func() {
		o.removeClient(pc)
		log.Infof("Client %x disconnected", pc.clientID)
	}()

	for {
		select {
		case <-o.ctx.Done():
			return
		default:
		}

		data, err := pc.conn.ReadPacket()
		if err != nil {
			log.Errorf("Read from client %x: %v", pc.clientID, err)
			return
		}
		if len(data) == 0 {
			continue
		}

		// Extract destination IP from the IP packet
		dstIP, err := packetDstIP(data)
		if err != nil {
			log.Debugf("Dropping malformed packet from %x: %v", pc.clientID, err)
			continue
		}

		// Find the target client by destination IP
		o.mu.RLock()
		target := o.findPeerByIP(dstIP)
		o.mu.RUnlock()

		if target == nil {
			log.Debugf("No route for %s from client %x", net.IP(dstIP), pc.clientID)
			continue
		}

		// Forward packet to the destination client
		if err := target.conn.WritePacket(data); err != nil {
			log.Errorf("Write to client %x: %v", target.clientID, err)
		}
	}
}

// findPeerByIP looks up a connected client by destination IP.
func (o *Operator) findPeerByIP(dstIP []byte) *peerConn {
	addr, ok := netip.AddrFromSlice(dstIP)
	if !ok {
		return nil
	}
	return o.peers[addr]
}

func (o *Operator) removeClient(pc *peerConn) {
	o.mu.Lock()
	defer o.mu.Unlock()

	addr := pc.ip.Addr()
	if existing, ok := o.peers[addr]; ok && existing == pc {
		delete(o.peers, addr)
	}
	pc.conn.Close()
}

func (o *Operator) Close() error {
	o.cancel()
	if o.cfg.Listener != nil {
		o.cfg.Listener.Close()
	}

	o.mu.Lock()
	for _, pc := range o.peers {
		pc.conn.Close()
	}
	o.mu.Unlock()

	return nil
}

// ConnectedClients returns the number of currently connected clients.
func (o *Operator) ConnectedClients() int {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return len(o.peers)
}

// packetDstIP extracts the destination IP from an IP packet.
func packetDstIP(data []byte) ([]byte, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("empty packet")
	}
	version := data[0] >> 4
	switch version {
	case 4:
		if len(data) < ipv4.HeaderLen {
			return nil, fmt.Errorf("short IPv4 packet: %d", len(data))
		}
		return data[16:20], nil // IPv4 dst offset
	case 6:
		if len(data) < ipv6.HeaderLen {
			return nil, fmt.Errorf("short IPv6 packet: %d", len(data))
		}
		return data[24:40], nil // IPv6 dst offset
	default:
		return nil, fmt.Errorf("unknown IP version: %d", version)
	}
}
