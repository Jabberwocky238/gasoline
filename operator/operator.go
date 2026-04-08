package operator

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/stats"
	"github.com/jabberwocky238/gasoline/transport"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type SessionIDType [common.SessionIDLen]byte
type OperatorUUIDType [common.OperatorUUIDLen]byte
type VNetIDType [common.VNetIDLen]byte

type Config struct {
	// UUID is this operator's unique identifier
	UUID OperatorUUIDType
	// Auth resolver for per-VNet auth
	Auth auth.AuthResolver
	// ConfigFunc generates SessionConfig for each client after auth
	ConfigFn protocol.ConfigFunc
	// ClientListener accepts client transport connections
	ClientListener transport.Listener
	// OperatorListenAddr is the local TCP address to bind for inter-operator connections
	OperatorListenAddr string
	// OperatorExternalAddr is the address other operators should use to reach us
	OperatorExternalAddr string
	// StatsAddr is the HTTP address for the stats API (empty = disabled)
	StatsAddr string
	// DiscoverAddrs is a list of seed operator addresses for bootstrap discovery
	DiscoverAddrs []string
}

// Operator accepts client connections, decrypts packets, and routes them
// to the correct client by destination IP.
type Operator struct {
	ctx    context.Context
	cancel context.CancelFunc

	cfg *Config

	clients   *ClientTable
	operators *OperatorTable
	Registry  *Registry
	Stats     *stats.Engine
	VNetPools *VNetPoolMap

	// TCP listener for inter-operator connections
	opListener net.Listener
}

func New(cfg *Config) *Operator {
	ctx, cancel := context.WithCancel(context.Background())
	return &Operator{
		cfg:       cfg,
		ctx:       ctx,
		cancel:    cancel,
		clients:   NewClientTable(),
		operators: NewOperatorTable(),
		Registry:  NewRegistry(),
		Stats:     stats.New(cfg.StatsAddr),
	}
}

// Start begins accepting client and operator connections.
func (o *Operator) Start() error {
	// Validate: discover requires external addr
	if len(o.cfg.DiscoverAddrs) > 0 && o.cfg.OperatorExternalAddr == "" {
		return fmt.Errorf("--discover requires --op-listen to include an external endpoint (e.g. 0.0.0.0:6677;1.2.3.4:6677)")
	}

	// Client endpoint
	log.Infof("Client endpoint listening on %s", o.cfg.ClientListener.Addr())
	go o.routineAcceptClients()

	// Operator endpoint
	ln, err := net.Listen("tcp", o.cfg.OperatorListenAddr)
	if err != nil {
		return fmt.Errorf("operator listen on %s: %w", o.cfg.OperatorListenAddr, err)
	}
	o.opListener = ln
	log.Infof("Operator endpoint listening on %s", o.cfg.OperatorListenAddr)
	go o.routineAcceptOperators()

	// Stats API
	if err := o.Stats.Start(); err != nil {
		return fmt.Errorf("stats: %w", err)
	}

	// Bootstrap discovery
	if len(o.cfg.DiscoverAddrs) > 0 {
		go o.Bootstrap()
	}

	return nil
}

// routineAcceptClients accepts new clients (handshake already done by transport layer).
func (o *Operator) routineAcceptClients() {
	for {
		conn, result, err := o.cfg.ClientListener.Accept()
		if err != nil {
			select {
			case <-o.ctx.Done():
				return
			default:
				log.Errorf("Client accept failed: %v", err)
				continue
			}
		}
		if conn == nil || result == nil {
			return
		}

		cp := &ClientPeer{
			Conn:       conn,
			SessionID:  SessionIDType(result.Config.SessionID),
			VNetID:     VNetIDType(result.Config.VNetID),
			OperatorID: o.cfg.UUID,
			IP:         result.Config.IPPrefix,
			AllowedIPs: result.Config.AllowedRanges,
		}

		o.clients.Add(cp)
		o.Stats.Recorder.Register(cp.SessionID, [16]byte(cp.VNetID), "", conn.RemoteAddr())
		o.broadcastSessionSync(cp)

		log.Infof("Client %x connected, assigned %s from %s",
			result.ClientID, result.Config.IPPrefix, conn.RemoteAddr())

		go o.routineReadFromClient(cp)
	}
}

// routineAcceptOperators accepts incoming TCP connections from peer operators.
func (o *Operator) routineAcceptOperators() {
	for {
		conn, err := o.opListener.Accept()
		if err != nil {
			select {
			case <-o.ctx.Done():
				return
			default:
				log.Errorf("Operator accept failed: %v", err)
				continue
			}
		}

		// UUID is unknown until Register frame arrives
		peer := NewOperatorPeer(OperatorUUIDType{}, conn)
		log.Infof("Operator peer connected from %s", conn.RemoteAddr())

		go o.routineHandleOperator(peer)
	}
}

// routineHandleOperator handles frames from a peer operator.
func (o *Operator) routineHandleOperator(peer *OperatorPeer) {
	defer peer.Close()

	for {
		select {
		case <-o.ctx.Done():
			return
		default:
		}

		frame, err := peer.Recv()
		if err != nil {
			log.Errorf("Operator peer %s read error: %v", peer.RemoteAddr(), err)
			return
		}

		switch frame.Type {
		case MsgData:
			o.handleOperatorData(frame)
		case MsgControl:
			o.handleOperatorControl(peer, frame)
		default:
			log.Debugf("Unknown frame type %d from operator %s", frame.Type, peer.RemoteAddr())
		}
	}
}

// handleOperatorData processes a data frame forwarded from a peer operator.
func (o *Operator) handleOperatorData(frame *Frame) {
	df, err := ParseDataFrame(frame.Content)
	if err != nil {
		log.Debugf("Dropping malformed data frame: %v", err)
		return
	}

	dstIP, err := packetDstIP(df.Packet)
	if err != nil {
		log.Debugf("Dropping data frame with bad packet: %v", err)
		return
	}

	dstAddr, ok := netip.AddrFromSlice(dstIP)
	if !ok {
		return
	}

	target := o.clients.LookupByIP(dstAddr)
	if target == nil {
		log.Debugf("No local client for %s (vnet %x)", dstAddr, df.VNetID)
		return
	}

	o.Stats.Recorder.RecordTx(target.SessionID, uint64(len(df.Packet)))
	if err := target.Conn.WritePacket(df.Packet); err != nil {
		log.Errorf("Write to client %x: %v", target.SessionID, err)
	}
}

// handleOperatorControl processes a control frame from a peer operator.
func (o *Operator) handleOperatorControl(peer *OperatorPeer, frame *Frame) {
	cf, err := ParseControlFrame(frame.Content)
	if err != nil {
		log.Debugf("Dropping malformed control frame: %v", err)
		return
	}

	switch cf.Subtype {
	case CtrlPing:
		peer.SendControl(CtrlPong, cf.Payload)
	case CtrlPong:
		o.handlePong(peer, cf.Payload)
	case CtrlRegister:
		o.handleRegister(peer, cf.Payload)
	case CtrlRegisterAck:
		o.handleRegisterAck(peer, cf.Payload)
	case CtrlDiscoverReq:
		o.handleDiscoverReq(peer)
	case CtrlDiscoverResp:
		o.handleDiscoverResp(cf.Payload)
	case CtrlSessionSync:
		o.handleSessionSync(o.VNetPools, cf.Payload)
	case CtrlSessionRevoke:
		o.handleSessionRevoke(o.VNetPools, cf.Payload)
	default:
		log.Debugf("Unknown control subtype %d from %s", cf.Subtype, peer.RemoteAddr())
	}
}

// routineReadFromClient reads packets from a client and routes them.
func (o *Operator) routineReadFromClient(cp *ClientPeer) {
	defer func() {
		o.clients.Remove(cp)
		o.Stats.Recorder.Unregister(cp.SessionID)
		o.broadcastSessionRevoke(cp)
		cp.Conn.Close()
		log.Infof("Client %x disconnected", cp.SessionID)
	}()

	for {
		select {
		case <-o.ctx.Done():
			return
		default:
		}

		data, err := cp.Conn.ReadPacket()
		if err != nil {
			log.Errorf("Read from client %x: %v", cp.SessionID, err)
			return
		}
		if len(data) == 0 {
			continue
		}

		// Record incoming traffic
		o.Stats.Recorder.RecordRx(cp.SessionID, uint64(len(data)))

		// Rate limit check (per VNet)
		if !o.Stats.RateLimiter.Allow([16]byte(cp.VNetID), uint64(len(data))) {
			log.Debugf("Rate limited packet from %x", cp.SessionID)
			continue
		}

		dstIP, err := packetDstIP(data)
		if err != nil {
			log.Debugf("Dropping malformed packet from %x: %v", cp.SessionID, err)
			continue
		}

		dstAddr, ok := netip.AddrFromSlice(dstIP)
		if !ok {
			log.Debugf("Invalid dst IP from %x", cp.SessionID)
			continue
		}

		// Try local client first
		target := o.clients.LookupByIP(dstAddr)
		if target != nil {
			o.Stats.Recorder.RecordTx(target.SessionID, uint64(len(data)))
			if err := target.Conn.WritePacket(data); err != nil {
				log.Errorf("Write to client %x: %v", target.SessionID, err)
			}
			continue
		}

		// Try remote operator
		if o.forwardToRemoteOperator(cp, dstAddr, data) {
			continue
		}

		log.Debugf("No route for %s from client %x", net.IP(dstIP), cp.SessionID)
	}
}

// DialOperator connects to a remote operator and performs mutual registration.
func (o *Operator) DialOperator(addr string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial operator %s: %w", addr, err)
	}

	peer := NewOperatorPeer(OperatorUUIDType{}, conn)

	// Send our UUID + external addr as Register
	if err := peer.SendControl(CtrlRegister, encodeRegisterPayload(o.cfg.UUID, o.cfg.OperatorExternalAddr)); err != nil {
		peer.Close()
		return fmt.Errorf("send register to %s: %w", addr, err)
	}

	// Read RegisterAck to get remote UUID + external addr
	frame, err := peer.Recv()
	if err != nil {
		peer.Close()
		return fmt.Errorf("recv register ack from %s: %w", addr, err)
	}

	if frame.Type != MsgControl {
		peer.Close()
		return fmt.Errorf("unexpected frame type %d from %s", frame.Type, addr)
	}
	cf, err := ParseControlFrame(frame.Content)
	if err != nil {
		peer.Close()
		return fmt.Errorf("parse control from %s: %w", addr, err)
	}
	if cf.Subtype != CtrlRegisterAck {
		peer.Close()
		return fmt.Errorf("expected RegisterAck, got subtype %d from %s", cf.Subtype, addr)
	}

	remoteUUID, remoteAddr := decodeRegisterPayload(cf.Payload)
	copy(peer.UUID[:], remoteUUID[:])

	o.operators.Add(peer)
	o.Registry.SetOperator(peer.UUID, &OperatorEntry{Addr: remoteAddr})
	log.Infof("Registered with operator %x at %s", peer.UUID, remoteAddr)

	go o.routineHandleOperator(peer)
	return nil
}

// handleRegister processes an incoming CtrlRegister from a peer operator.
func (o *Operator) handleRegister(peer *OperatorPeer, payload []byte) {
	remoteUUID, remoteAddr := decodeRegisterPayload(payload)
	copy(peer.UUID[:], remoteUUID[:])

	// Reply with our UUID + external addr
	peer.SendControl(CtrlRegisterAck, encodeRegisterPayload(o.cfg.UUID, o.cfg.OperatorExternalAddr))

	o.operators.Add(peer)
	o.Registry.SetOperator(peer.UUID, &OperatorEntry{Addr: remoteAddr})
	log.Infof("Operator %x registered, external %s", peer.UUID, remoteAddr)
}

// handleRegisterAck processes an incoming CtrlRegisterAck from a peer operator.
func (o *Operator) handleRegisterAck(peer *OperatorPeer, payload []byte) {
	remoteUUID, remoteAddr := decodeRegisterPayload(payload)
	copy(peer.UUID[:], remoteUUID[:])

	o.operators.Add(peer)
	o.Registry.SetOperator(peer.UUID, &OperatorEntry{Addr: remoteAddr})
	log.Infof("Operator %x acked, external %s", peer.UUID, remoteAddr)
}

// encodeRegisterPayload encodes [uuid:16][addrLen:2][addr:N].
func encodeRegisterPayload(uuid OperatorUUIDType, addr string) []byte {
	buf := make([]byte, 16+2+len(addr))
	copy(buf[0:16], uuid[:])
	buf[16] = byte(len(addr) >> 8)
	buf[17] = byte(len(addr))
	copy(buf[18:], addr)
	return buf
}

// decodeRegisterPayload decodes [uuid:16][addrLen:2][addr:N].
func decodeRegisterPayload(payload []byte) (OperatorUUIDType, string) {
	var uuid OperatorUUIDType
	if len(payload) < 18 {
		if len(payload) >= 16 {
			copy(uuid[:], payload[:16])
		}
		return uuid, ""
	}
	copy(uuid[:], payload[:16])
	addrLen := int(payload[16])<<8 | int(payload[17])
	if 18+addrLen > len(payload) {
		return uuid, ""
	}
	return uuid, string(payload[18 : 18+addrLen])
}

// handlePong processes a Pong response and updates PingCost in Registry.
func (o *Operator) handlePong(peer *OperatorPeer, payload []byte) {
	sentNano, err := DecodePingPayload(payload)
	if err != nil {
		log.Debugf("Bad pong payload from %s: %v", peer.RemoteAddr(), err)
		return
	}

	rtt := time.Duration(time.Now().UnixNano() - sentNano)

	entry, ok := o.Registry.GetOperator(peer.UUID)
	if !ok {
		log.Warnf("handlePong: operator %x not in registry", peer.UUID)
		return
	}
	entry.PingCost = rtt
	entry.LastPing = time.Now()
	o.Registry.SetOperator(peer.UUID, entry)

	log.Infof("Pong from %x: RTT=%v", peer.UUID, rtt)
}

// PingOperator sends a Ping to a remote operator by UUID.
func (o *Operator) PingOperator(uuid OperatorUUIDType) error {
	peer, ok := o.operators.Get(uuid)
	if !ok {
		return fmt.Errorf("operator %x not found", uuid)
	}
	return peer.SendControl(CtrlPing, EncodePingPayload(time.Now().UnixNano()))
}

func (o *Operator) Close() error {
	o.cancel()

	if o.cfg.ClientListener != nil {
		o.cfg.ClientListener.Close()
	}
	if o.opListener != nil {
		o.opListener.Close()
	}

	o.clients.CloseAll()
	o.operators.CloseAll()
	o.Stats.Close()

	return nil
}

// ConnectedClients returns the number of currently connected clients.
func (o *Operator) ConnectedClients() int {
	return o.clients.Len()
}

// ConnectedOperators returns the number of connected peer operators.
func (o *Operator) ConnectedOperators() int {
	return o.operators.Len()
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
		return data[16:20], nil
	case 6:
		if len(data) < ipv6.HeaderLen {
			return nil, fmt.Errorf("short IPv6 packet: %d", len(data))
		}
		return data[24:40], nil
	default:
		return nil, fmt.Errorf("unknown IP version: %d", version)
	}
}
