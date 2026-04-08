package operator

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/stats"
	"github.com/jabberwocky238/gasoline/transport"
	"github.com/jabberwocky238/gasoline/transport/quic"
	"github.com/jabberwocky238/gasoline/transport/tcp"
	"github.com/jabberwocky238/gasoline/transport/udp"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type SessionIDType [common.SessionIDLen]byte
type OperatorUUIDType [common.OperatorUUIDLen]byte
type VNetIDType [common.VNetIDLen]byte


// Operator accepts client connections, decrypts packets, and routes them
// to the correct client by destination IP.
type Operator struct {
	ctx    context.Context
	cancel context.CancelFunc

	cfg *common.OperatorConfig

	uuid      OperatorUUIDType
	serverPub protocol.PublicKey
	resolver  auth.AuthResolver

	clientListener transport.Listener
	clients        *ClientTable
	operators      *OperatorTable
	Registry       *Registry
	Stats          *stats.Engine
	VNetPools      *VNetPoolMap

	opListener net.Listener
}

// New creates an Operator from declarative config.
// Parses network pools, generates keypair, builds auth resolver and transport listener.
func New(cfg *common.OperatorConfig) (*Operator, error) {
	// UUID: use provided or generate random
	var uuid OperatorUUIDType
	if cfg.UUID != nil {
		uuid = OperatorUUIDType(*cfg.UUID)
	} else {
		rand.Read(uuid[:])
	}

	var pools *VNetPoolMap
	var serverPub protocol.PublicKey
	var resolver *auth.MapResolver
	var clientListener transport.Listener

	// VNet pools, auth, keypair, listener — only if Network is configured
	if cfg.Network != "" {
		seed, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
		var err error
		pools, err = ParseVNetPools(cfg.Network, uint32(seed.Int64()))
		if err != nil {
			return nil, fmt.Errorf("network: %w", err)
		}
		for vnetID, pool := range pools.All() {
			log.Infof("VNet %x: %s", vnetID, pool.Prefix)
		}

		serverPriv, err := protocol.NewPrivateKey()
		if err != nil {
			return nil, fmt.Errorf("generate server key: %w", err)
		}
		serverPub = serverPriv.PublicKey()
		log.Infof("Server public key: %s", serverPub.ToBase64())

		defaultAuth, err := auth.ParseServerAuth(cfg.AuthStr)
		if err != nil {
			return nil, fmt.Errorf("auth: %w", err)
		}
		resolver = auth.NewMapResolver(defaultAuth)
		for vnetID, authStr := range cfg.NetworkAuth {
			vnetAuth, err := auth.ParseServerAuth(authStr)
			if err != nil {
				return nil, fmt.Errorf("auth for vnet %x: %w", vnetID, err)
			}
			resolver.Set(vnetID, vnetAuth)
			log.Infof("VNet %x: auth=%s", vnetID, vnetAuth.Type())
		}

		configFn := func(clientID [16]byte, vnetID [16]byte) (*protocol.SessionConfig, error) {
			pool, ok := pools.Get(VNetIDType(vnetID))
			if !ok {
				return nil, fmt.Errorf("unknown vnet %x", vnetID)
			}
			clientIP, err := pool.AllocateIP()
			if err != nil {
				return nil, err
			}
			clientPriv, err := protocol.NewPrivateKey()
			if err != nil {
				return nil, err
			}
			h := sha256.New()
			h.Write(clientID[:])
			var ts [8]byte
			binary.BigEndian.PutUint64(ts[:], uint64(time.Now().UnixNano()))
			h.Write(ts[:])
			var sessionID [16]byte
			copy(sessionID[:], h.Sum(nil)[:16])
			return &protocol.SessionConfig{
				SessionID:        sessionID,
				VNetID:           vnetID,
				ClientPrivateKey: clientPriv,
				ServerPublicKey:  serverPub,
				IPPrefix:         netip.PrefixFrom(clientIP, 32),
				AllowedRanges:    []netip.Prefix{pool.Prefix},
			}, nil
		}

		clientListener, err = createListener(cfg.Transport, cfg.ListenAddr, resolver, configFn)
		if err != nil {
			return nil, fmt.Errorf("listener: %w", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	op := &Operator{
		cfg:            cfg,
		ctx:            ctx,
		cancel:         cancel,
		uuid:           uuid,
		serverPub:      serverPub,
		resolver:       resolver,
		clientListener: clientListener,
		clients:        NewClientTable(),
		operators:      NewOperatorTable(),
		Registry:       NewRegistry(),
		Stats:          stats.New(cfg.StatsAddr),
		VNetPools:      pools,
	}

	log.Infof("Operator UUID: %x", uuid)
	return op, nil
}

func (o *Operator) UUID() OperatorUUIDType { return o.uuid }

// Start begins accepting client and operator connections.
func (o *Operator) Start() error {
	if len(o.cfg.DiscoverAddrs) > 0 && o.cfg.OpExternalAddr == "" {
		return fmt.Errorf("--discover requires --op-listen to include an external endpoint")
	}

	if o.clientListener != nil {
		log.Infof("Client endpoint listening on %s", o.clientListener.Addr())
		go o.routineAcceptClients()
	}

	ln, err := net.Listen("tcp", o.cfg.OpListenAddr)
	if err != nil {
		return fmt.Errorf("operator listen on %s: %w", o.cfg.OpListenAddr, err)
	}
	o.opListener = ln
	log.Infof("Operator endpoint listening on %s", o.cfg.OpListenAddr)
	go o.routineAcceptOperators()

	if err := o.Stats.Start(); err != nil {
		return fmt.Errorf("stats: %w", err)
	}

	if len(o.cfg.DiscoverAddrs) > 0 {
		go o.Bootstrap()
	}

	return nil
}

func (o *Operator) routineAcceptClients() {
	for {
		conn, result, err := o.clientListener.Accept()
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
			OperatorID: o.uuid,
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
		peer := NewOperatorPeer(OperatorUUIDType{}, conn)
		log.Infof("Operator peer connected from %s", conn.RemoteAddr())
		go o.routineHandleOperator(peer)
	}
}

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

		o.Stats.Recorder.RecordRx(cp.SessionID, uint64(len(data)))

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

		target := o.clients.LookupByIP(dstAddr)
		if target != nil {
			o.Stats.Recorder.RecordTx(target.SessionID, uint64(len(data)))
			if err := target.Conn.WritePacket(data); err != nil {
				log.Errorf("Write to client %x: %v", target.SessionID, err)
			}
			continue
		}

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

	if err := peer.SendControl(CtrlRegister, encodeRegisterPayload(o.uuid, o.cfg.OpExternalAddr)); err != nil {
		peer.Close()
		return fmt.Errorf("send register to %s: %w", addr, err)
	}

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

func (o *Operator) handleRegister(peer *OperatorPeer, payload []byte) {
	remoteUUID, remoteAddr := decodeRegisterPayload(payload)
	copy(peer.UUID[:], remoteUUID[:])

	peer.SendControl(CtrlRegisterAck, encodeRegisterPayload(o.uuid, o.cfg.OpExternalAddr))

	o.operators.Add(peer)
	o.Registry.SetOperator(peer.UUID, &OperatorEntry{Addr: remoteAddr})
	log.Infof("Operator %x registered, external %s", peer.UUID, remoteAddr)
}

func (o *Operator) handleRegisterAck(peer *OperatorPeer, payload []byte) {
	remoteUUID, remoteAddr := decodeRegisterPayload(payload)
	copy(peer.UUID[:], remoteUUID[:])

	o.operators.Add(peer)
	o.Registry.SetOperator(peer.UUID, &OperatorEntry{Addr: remoteAddr})
	log.Infof("Operator %x acked, external %s", peer.UUID, remoteAddr)
}

func encodeRegisterPayload(uuid OperatorUUIDType, addr string) []byte {
	buf := make([]byte, 16+2+len(addr))
	copy(buf[0:16], uuid[:])
	buf[16] = byte(len(addr) >> 8)
	buf[17] = byte(len(addr))
	copy(buf[18:], addr)
	return buf
}

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

func (o *Operator) PingOperator(uuid OperatorUUIDType) error {
	peer, ok := o.operators.Get(uuid)
	if !ok {
		return fmt.Errorf("operator %x not found", uuid)
	}
	return peer.SendControl(CtrlPing, EncodePingPayload(time.Now().UnixNano()))
}

func (o *Operator) Close() error {
	o.cancel()

	if o.clientListener != nil {
		o.clientListener.Close()
	}
	if o.opListener != nil {
		o.opListener.Close()
	}

	o.clients.CloseAll()
	o.operators.CloseAll()
	o.Stats.Close()

	return nil
}

func (o *Operator) ConnectedClients() int  { return o.clients.Len() }
func (o *Operator) ConnectedOperators() int { return o.operators.Len() }

func createListener(transportType, addr string, resolver auth.AuthResolver, configFn protocol.ConfigFunc) (transport.Listener, error) {
	switch transportType {
	case "tcp":
		return tcp.NewListener(addr, resolver, configFn)
	case "udp":
		return udp.NewListener(addr, resolver, configFn)
	case "quic":
		tlsConf, err := quic.GenerateServerTLS()
		if err != nil {
			return nil, err
		}
		return quic.NewListener(addr, resolver, configFn, tlsConf)
	default:
		return nil, fmt.Errorf("unknown transport: %s", transportType)
	}
}

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
