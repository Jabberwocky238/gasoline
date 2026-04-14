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
	transportTls "github.com/jabberwocky238/gasoline/transport/tls"
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
	dataConn *net.UDPConn
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
		for vni, pool := range pools.All() {
			logger.Infof("VNet %s: %s", vni, pool.Prefix)
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
		for vni, authStr := range cfg.NetworkAuth {
			vnetAuth, err := auth.ParseServerAuth(authStr)
			if err != nil {
				cancel()
				return nil, fmt.Errorf("auth for vni %s: %w", vni, err)
			}
			resolver.Set(vni, vnetAuth)
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
		ctrlCfg.OnSessionSync = func(vni common.VNI, _ common.ClientID, ip netip.Addr) {
			if pool, ok := pools.Get(vni); ok {
				pool.ReserveIP(ip)
			}
		}
		ctrlCfg.OnSessionRevoke = func(vni common.VNI, _ [16]byte, _ common.ClientID, ip netip.Addr) {
			if pool, ok := pools.Get(vni); ok {
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
	readBuf := make([]byte, common.MaxVxlanPayload)
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

		df := common.GetFrame()
		if err := df.Decode(readBuf[:n]); err != nil {
			common.PutFrame(df)
			continue
		}

		// Pure (VNI, dstCID) forwarding — no inner IP parsing.
		target := o.clients.LookupByCID(df.VNI, df.DstCID)
		if target == nil {
			common.PutFrame(df)
			continue
		}

		o.Stats.Recorder.RecordTx(target.SessionID, uint64(len(df.Packet)))
		target.Conn.WritePacket(df.Packet)
		common.PutFrame(df)
	}
}

// forwardToRemote wraps the packet in VXLAN (inner Eth dst MAC = dstClientID)
// and sends it to the owning operator. Caller provides srcClientID & dstClientID —
// no packet-payload inspection happens here.
func (o *Operator) forwardToRemote(srcVNI common.VNI, srcClientID, dstClientID common.ClientID, opUUID [16]byte, packet []byte) bool {
	version := common.InnerIPVersion(packet)
	mtu := common.MTUFor(version)
	if mtu == 0 || len(packet) > mtu {
		o.log.Warnf("forwardToRemote: invalid/oversize IPv%d packet %d, dropping", version, len(packet))
		return false
	}
	if opUUID == o.Ctrl.UUID() {
		return false
	}

	peer, ok := o.Ctrl.Peers.Get(opUUID)
	if !ok || peer.UDPAddr == nil {
		return false
	}

	df := common.GetFrame()
	wire := df.Encode(srcVNI, srcClientID, dstClientID, packet)
	_, err := o.dataConn.WriteToUDP(wire, peer.UDPAddr)
	common.PutFrame(df)
	if err != nil {
		o.log.Errorf("forwardToRemote WriteToUDP: %v", err)
		return false
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
			ClientID:   result.ClientID,
			VNI:        result.Config.VNI,
			OperatorID: o.Ctrl.UUID(),
			IP:         result.Config.IPPrefix,
			AllowedIPs: result.Config.AllowedRanges,
		}

		o.clients.Add(cp)
		o.Stats.Recorder.Register(cp.SessionID, cp.VNI, "", conn.RemoteAddr())
		o.Ctrl.BroadcastSessionSync(cp.SessionID, cp.VNI, cp.ClientID, cp.IP.Addr())

		o.log.Infof("Client %x connected, assigned %s from %s",
			result.ClientID, result.Config.IPPrefix, conn.RemoteAddr())
		go o.routineReadFromClient(cp)
	}
}

func (o *Operator) routineReadFromClient(cp *ClientPeer) {
	defer func() {
		o.clients.Remove(cp)
		o.Stats.Recorder.Unregister(cp.SessionID)
		o.Ctrl.BroadcastSessionRevoke(cp.SessionID, cp.VNI)
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
		payload := readBuf[:n]
		version := common.InnerIPVersion(payload)
		mtu := common.MTUFor(version)
		if mtu == 0 {
			o.log.Warnf("Client %x sent packet with bad IP version 0x%02x, dropping", cp.SessionID, payload[0])
			continue
		}
		if n > mtu {
			o.log.Warnf("Client %x sent oversize IPv%d packet %d > %d, dropping", cp.SessionID, version, n, mtu)
			continue
		}

		o.Stats.Recorder.RecordRx(cp.SessionID, uint64(len(payload)))
		if !o.Stats.RateLimiter.Allow(cp.VNI, uint64(len(payload))) {
			continue
		}

		// Ingress-time translation: client sends raw IP, operator resolves
		// dstIP → dstClientID once via the registry. After that point, all
		// forwarding is pure (VNI, ClientID) — inner IP payload is never
		// inspected again.
		dstIPRaw, err := packetDstIP(payload)
		if err != nil {
			continue
		}
		dstAddr, ok := netip.AddrFromSlice(dstIPRaw)
		if !ok {
			continue
		}

		// Local delivery (fast path: local ClientTable by IP).
		if target := o.clients.LookupByIP(dstAddr); target != nil {
			o.Stats.Recorder.RecordTx(target.SessionID, uint64(len(payload)))
			target.Conn.WritePacket(payload)
			continue
		}

		// Remote delivery: find dstClientID + owning operator, forward via VXLAN.
		if o.dataConn != nil {
			_, dstCID, opUUID, found := o.Ctrl.LookupRemoteSessionByIP(cp.VNI, dstAddr)
			if found && o.forwardToRemote(cp.VNI, cp.ClientID, dstCID, opUUID, payload) {
				continue
			}
		}

		o.log.Debugf("No route for %s from client %x", dstAddr, cp.SessionID)
	}
}

// routineReaper periodically scans for idle clients and disconnects them.
// Session liveness is determined by transport.Conn.LastActive().
func (o *Operator) routineReaper() {
	const idleTimeout = 60 * time.Second
	ticker := time.NewTicker(idleTimeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-o.ctx.Done():
			return
		case <-ticker.C:
		}

		now := time.Now()
		o.clients.mu.RLock()
		var stale []*ClientPeer
		for _, cp := range o.clients.byIP {
			idle := now.Sub(cp.Conn.LastActive())
			if idle > idleTimeout {
				stale = append(stale, cp)
			}
		}
		o.clients.mu.RUnlock()

		for _, cp := range stale {
			idle := now.Sub(cp.Conn.LastActive())
			o.log.Warnf("Reaping idle client %x (idle %v)", cp.SessionID, idle.Round(time.Second))
			cp.Conn.Close()
		}
	}
}

// --------------- Helpers ---------------

func makeConfigFunc(pools *VNetPoolMap, serverPub encryption.PublicKey) protocol.ConfigFunc {
	return func(clientID common.ClientID, vni common.VNI) (*protocol.SessionConfig, error) {
		pool, ok := pools.Get(vni)
		if !ok {
			return nil, fmt.Errorf("unknown vni %s", vni)
		}
		// Generate sessionID BEFORE allocating IP — IPv6 derivation needs it.
		h := sha256.New()
		h.Write(clientID[:])
		var ts [8]byte
		binary.BigEndian.PutUint64(ts[:], uint64(time.Now().UnixNano()))
		h.Write(ts[:])
		var sessionID [16]byte
		copy(sessionID[:], h.Sum(nil)[:16])

		clientIP, err := pool.AllocateIP(sessionID)
		if err != nil {
			return nil, err
		}
		clientPriv, err := encryption.NewPrivateKey()
		if err != nil {
			return nil, err
		}

		// Host prefix bits: /32 for v4, /128 for v6
		hostBits := 32
		if !clientIP.Is4() {
			hostBits = 128
		}
		return &protocol.SessionConfig{
			SessionID:        sessionID,
			VNI:              vni,
			ClientPrivateKey: clientPriv,
			ServerPublicKey:  serverPub,
			IPPrefix:         netip.PrefixFrom(clientIP, hostBits),
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
	case "tls":
		tlsConf, err := transportQuic.GenerateServerTLS()
		if err != nil {
			return nil, err
		}
		return transportTls.NewListener(addr, resolver, configFn, tlsConf)
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
