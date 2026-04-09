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
	"github.com/jabberwocky238/gasoline/operator/ctrl"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/protocol/encryption"
	"github.com/jabberwocky238/gasoline/stats"
	"github.com/jabberwocky238/gasoline/transport"
	transportQuic "github.com/jabberwocky238/gasoline/transport/quic"
	transportTcp "github.com/jabberwocky238/gasoline/transport/tcp"
	transportUdp "github.com/jabberwocky238/gasoline/transport/udp"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type Operator struct {
	ctx    context.Context
	cancel context.CancelFunc
	log    *log.Logger

	Ctrl *ctrl.ControlPlane

	clientListener transport.Listener
	clients        *ClientTable
	Stats          *stats.Engine
	VNetPools      *VNetPoolMap

	// UDP data plane for inter-operator packet forwarding.
	dataConn  *net.UDPConn
	framePool *FramePool
	sendQ     *sendQueue
}

func New(cfg *common.OperatorConfig) (*Operator, error) {
	logger := log.New()
	if cfg.LogLevel != "" {
		lvl, err := log.ParseLevel(cfg.LogLevel)
		if err == nil {
			logger.SetLevel(lvl)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	var pools *VNetPoolMap
	var clientListener transport.Listener

	if cfg.Network != "" {
		seed, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
		var err error
		pools, err = ParseVNetPools(cfg.Network, uint32(seed.Int64()))
		if err != nil {
			cancel()
			return nil, fmt.Errorf("network: %w", err)
		}
		for vnetID, pool := range pools.All() {
			logger.Infof("VNet %x: %s", vnetID, pool.Prefix)
		}

		serverPriv, err := encryption.NewPrivateKey()
		if err != nil {
			cancel()
			return nil, fmt.Errorf("generate server key: %w", err)
		}
		serverPub := serverPriv.PublicKey()
		logger.Infof("Server public key: %s", serverPub.ToBase64())

		defaultAuth, err := auth.ParseServerAuth(cfg.AuthStr)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("auth: %w", err)
		}
		resolver := auth.NewMapResolver(defaultAuth)
		for vnetID, authStr := range cfg.NetworkAuth {
			vnetAuth, err := auth.ParseServerAuth(authStr)
			if err != nil {
				cancel()
				return nil, fmt.Errorf("auth for vnet %x: %w", vnetID, err)
			}
			resolver.Set(vnetID, vnetAuth)
		}

		configFn := makeConfigFunc(pools, serverPub)
		clientListener, err = createClientListener(cfg.Transport, cfg.ListenAddr, resolver, configFn)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("listener: %w", err)
		}
	}

	op := &Operator{
		ctx:            ctx,
		cancel:         cancel,
		log:            logger,
		clientListener: clientListener,
		clients:        NewClientTable(),
		Stats:          stats.New(cfg.StatsAddr),
		VNetPools:      pools,
	}

	ctrlCfg := &ctrl.Config{
		UUID:          cfg.UUID,
		ListenAddr:    cfg.OpListenAddr,
		ExternalAddr:  cfg.OpExternalAddr,
		DiscoverAddrs: cfg.DiscoverAddrs,
		Log:           logger,
	}
	if pools != nil {
		ctrlCfg.OnSessionSync = func(vnetID [16]byte, ip netip.Addr) {
			if pool, ok := pools.Get(vnetID); ok {
				pool.ReserveIP(ip)
			}
		}
		ctrlCfg.OnSessionRevoke = func(vnetID [16]byte, _ [16]byte, ip netip.Addr) {
			if pool, ok := pools.Get(vnetID); ok {
				pool.UnreserveIP(ip)
			}
		}
	}
	op.Ctrl = ctrl.New(ctrlCfg)

	return op, nil
}

func (o *Operator) UUID() [16]byte          { return o.Ctrl.UUID() }
func (o *Operator) GRPCAddr() string        { return o.Ctrl.GRPCAddr() }
func (o *Operator) ClientAddr() string      { if o.clientListener != nil { return o.clientListener.Addr() }; return "" }
func (o *Operator) ConnectedClients() int   { return o.clients.Len() }
func (o *Operator) ConnectedOperators() int { return o.Ctrl.Peers.Len() }

func (o *Operator) Start() error {
	if err := o.Ctrl.Start(); err != nil {
		return err
	}

	// UDP data plane: bind on same port as gRPC (TCP and UDP can share a port)
	if grpcAddr := o.Ctrl.GRPCAddr(); grpcAddr != "" {
		udpAddr, err := net.ResolveUDPAddr("udp", grpcAddr)
		if err != nil {
			return fmt.Errorf("resolve data udp addr: %w", err)
		}
		o.dataConn, err = net.ListenUDP("udp", udpAddr)
		if err != nil {
			return fmt.Errorf("data udp listen on %s: %w", grpcAddr, err)
		}
		o.framePool = NewFramePool(256)
		o.sendQ = newSendQueue(o.dataConn, 4096)
		go o.sendQ.Run()
		o.log.Infof("Data plane UDP listening on %s", o.dataConn.LocalAddr())
		go o.routineDataRecv()
	}

	if o.clientListener != nil {
		o.log.Infof("Client endpoint listening on %s", o.clientListener.Addr())
		go o.routineAcceptClients()
	}

	// Session reaper: periodically kick idle clients
	go o.routineReaper()

	if err := o.Stats.Start(); err != nil {
		return fmt.Errorf("stats: %w", err)
	}
	return nil
}

func (o *Operator) Close() error {
	o.cancel()
	o.Ctrl.Stop()
	if o.sendQ != nil {
		o.sendQ.Close()
	}
	if o.dataConn != nil {
		o.dataConn.Close()
	}
	if o.clientListener != nil {
		o.clientListener.Close()
	}
	o.clients.CloseAll()
	o.Stats.Close()
	return nil
}

// --------------- UDP data plane (inter-operator) ---------------

// routineDataRecv reads data frames from other operators via UDP
// and delivers packets to local clients.
func (o *Operator) routineDataRecv() {
	readBuf := make([]byte, maxDatagramSize)
	for {
		select {
		case <-o.ctx.Done():
			return
		default:
		}

		n, _, err := o.dataConn.ReadFromUDP(readBuf)
		if err != nil {
			select {
			case <-o.ctx.Done():
			default:
				o.log.Errorf("Data recv: %v", err)
			}
			return
		}

		df := o.framePool.Get()
		if err := df.Decode(readBuf[:n]); err != nil {
			o.framePool.Put(df)
			continue
		}

		dstIP, err := packetDstIP(df.Packet)
		if err != nil {
			o.framePool.Put(df)
			continue
		}
		dstAddr, ok := netip.AddrFromSlice(dstIP)
		if !ok {
			o.framePool.Put(df)
			continue
		}

		target := o.clients.LookupByIP(dstAddr)
		if target == nil {
			o.framePool.Put(df)
			continue
		}

		// Wrap with data prefix before sending to local client
		pBuf := common.GetBuffer()
		prefixed := (*pBuf)[:1+len(df.Packet)]
		prefixed[0] = common.PacketData
		copy(prefixed[1:], df.Packet)

		o.Stats.Recorder.RecordTx(target.SessionID, uint64(len(df.Packet)))
		target.Conn.WritePacket(prefixed)
		common.PutBuffer(pBuf)
		o.framePool.Put(df)
	}
}

// forwardToRemote looks up the remote operator for dstAddr and enqueues the packet for UDP send.
func (o *Operator) forwardToRemote(srcVNetID [16]byte, dstAddr netip.Addr, packet []byte) bool {
	opUUID, found := o.Ctrl.LookupRemoteSession(srcVNetID, dstAddr)
	if !found {
		return false
	}
	if opUUID == o.Ctrl.UUID() {
		return false
	}

	peer, ok := o.Ctrl.Peers.Get(opUUID)
	if !ok || peer.UDPAddr == nil {
		return false
	}

	df := o.framePool.Get()
	wire := df.Encode(srcVNetID, packet)
	// Copy into pooled buffer since df is recycled immediately
	buf := common.GetBuffer()
	n := copy(*buf, wire)
	o.framePool.Put(df)

	if !o.sendQ.Enqueue(peer.UDPAddr, (*buf)[:n], buf) {
		common.PutBuffer(buf)
		o.log.Debugf("Send queue full, dropped packet for %s", dstAddr)
	}
	return true
}

// --------------- Client data plane ---------------

func (o *Operator) routineAcceptClients() {
	for {
		conn, result, err := o.clientListener.Accept()
		if err != nil {
			select {
			case <-o.ctx.Done():
				return
			default:
				o.log.Errorf("Client accept failed: %v", err)
				continue
			}
		}
		if conn == nil || result == nil {
			return
		}

		cp := &ClientPeer{
			Conn:       conn,
			SessionID:  result.Config.SessionID,
			VNetID:     result.Config.VNetID,
			OperatorID: o.Ctrl.UUID(),
			IP:         result.Config.IPPrefix,
			AllowedIPs: result.Config.AllowedRanges,
		}

		cp.Touch()
		o.clients.Add(cp)
		o.Stats.Recorder.Register(cp.SessionID, cp.VNetID, "", conn.RemoteAddr())
		o.Ctrl.BroadcastSessionSync(cp.SessionID, cp.VNetID, cp.IP.Addr())

		o.log.Infof("Client %x connected, assigned %s from %s",
			result.ClientID, result.Config.IPPrefix, conn.RemoteAddr())
		go o.routineReadFromClient(cp)
	}
}

func (o *Operator) routineReadFromClient(cp *ClientPeer) {
	defer func() {
		o.clients.Remove(cp)
		o.Stats.Recorder.Unregister(cp.SessionID)
		o.Ctrl.BroadcastSessionRevoke(cp.SessionID, cp.VNetID)
		cp.Conn.Close()
		o.log.Infof("Client %x disconnected", cp.SessionID)
	}()

	bufPtr := common.GetBuffer()
	defer common.PutBuffer(bufPtr)
	readBuf := *bufPtr
	for {
		select {
		case <-o.ctx.Done():
			return
		default:
		}

		n, err := cp.Conn.ReadPacket(readBuf)
		if err != nil {
			o.log.Errorf("Read from client %x: %v", cp.SessionID, err)
			return
		}
		if n < 1 {
			continue
		}
		data := readBuf[:n]

		// Every packet (data or keepalive) refreshes the session
		cp.Touch()

		pktType := data[0]
		payload := data[1:]

		switch pktType {
		case common.PacketKeepalive:
			o.log.Debugf("Keepalive from client %x", cp.SessionID)
			continue

		case common.PacketData:
			// fall through to routing

		default:
			o.log.Debugf("Unknown packet type 0x%02x from client %x", pktType, cp.SessionID)
			continue
		}

		if len(payload) == 0 {
			continue
		}

		o.Stats.Recorder.RecordRx(cp.SessionID, uint64(len(payload)))
		if !o.Stats.RateLimiter.Allow(cp.VNetID, uint64(len(payload))) {
			continue
		}

		dstIP, err := packetDstIP(payload)
		if err != nil {
			continue
		}
		dstAddr, ok := netip.AddrFromSlice(dstIP)
		if !ok {
			continue
		}

		// Local delivery — add data prefix before sending to peer client
		if target := o.clients.LookupByIP(dstAddr); target != nil {
			o.Stats.Recorder.RecordTx(target.SessionID, uint64(len(payload)))
			target.Conn.WritePacket(data) // data already has prefix
			continue
		}

		// Remote forwarding via UDP (inter-operator, no prefix — raw IP)
		if o.dataConn != nil && o.forwardToRemote(cp.VNetID, dstAddr, payload) {
			continue
		}

		o.log.Debugf("No route for %s from client %x", dstAddr, cp.SessionID)
	}
}

// routineReaper periodically scans for idle clients and disconnects them.
func (o *Operator) routineReaper() {
	timeout := time.Duration(common.KeepaliveTimeout) * time.Second
	ticker := time.NewTicker(timeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-o.ctx.Done():
			return
		case <-ticker.C:
		}

		o.clients.mu.RLock()
		var stale []*ClientPeer
		for _, cp := range o.clients.peers {
			if cp.IdleDuration() > timeout {
				stale = append(stale, cp)
			}
		}
		o.clients.mu.RUnlock()

		for _, cp := range stale {
			o.log.Warnf("Reaping idle client %x (idle %v)", cp.SessionID, cp.IdleDuration().Round(time.Second))
			cp.Conn.Close() // triggers routineReadFromClient to exit and clean up
		}
	}
}

// --------------- Helpers ---------------

func makeConfigFunc(pools *VNetPoolMap, serverPub encryption.PublicKey) protocol.ConfigFunc {
	return func(clientID [16]byte, vnetID [16]byte) (*protocol.SessionConfig, error) {
		pool, ok := pools.Get(vnetID)
		if !ok {
			return nil, fmt.Errorf("unknown vnet %x", vnetID)
		}
		clientIP, err := pool.AllocateIP()
		if err != nil {
			return nil, err
		}
		clientPriv, err := encryption.NewPrivateKey()
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
}

func createClientListener(transportType, addr string, resolver auth.AuthResolver, configFn protocol.ConfigFunc) (transport.Listener, error) {
	switch transportType {
	case "tcp":
		return transportTcp.NewListener(addr, resolver, configFn)
	case "udp":
		return transportUdp.NewListener(addr, resolver, configFn)
	case "quic":
		tlsConf, err := transportQuic.GenerateServerTLS()
		if err != nil {
			return nil, err
		}
		return transportQuic.NewListener(addr, resolver, configFn, tlsConf)
	default:
		return nil, fmt.Errorf("unknown transport: %s", transportType)
	}
}

func packetDstIP(data []byte) ([]byte, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("empty packet")
	}
	switch data[0] >> 4 {
	case 4:
		if len(data) < ipv4.HeaderLen {
			return nil, fmt.Errorf("short IPv4")
		}
		return data[16:20], nil
	case 6:
		if len(data) < ipv6.HeaderLen {
			return nil, fmt.Errorf("short IPv6")
		}
		return data[24:40], nil
	default:
		return nil, fmt.Errorf("unknown IP version")
	}
}
