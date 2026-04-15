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
	"github.com/jabberwocky238/gasoline/operator/vxlan"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/protocol/encryption"
	"github.com/jabberwocky238/gasoline/stats"
	"github.com/jabberwocky238/gasoline/transport"
	transportQuic "github.com/jabberwocky238/gasoline/transport/quic"
	transportTcp "github.com/jabberwocky238/gasoline/transport/tcp"
	transportTls "github.com/jabberwocky238/gasoline/transport/tls"
	transportUdp "github.com/jabberwocky238/gasoline/transport/udp"
)

// Operator wires together: client transport listener, control plane (gRPC),
// and a vxlan.Plane that handles all L2 forwarding (local + inter-operator).
//
// The data plane is now entirely owned by Plane; Operator only provides
// orchestration (accept clients, register them as Ports on the Plane,
// shovel client→Conn frames into Plane.Forward).
type Operator struct {
	ctx    context.Context
	cancel context.CancelFunc
	log    *log.Logger

	Ctrl *ctrl.ControlPlane

	clientListeners map[string]transport.Listener // keyed by transport kind
	clients         *ClientTable
	Stats           *stats.Engine
	VNetPools       *VNetPoolMap

	dataPort *net.UDPConn
	plane    *vxlan.Plane
}

// connPort wraps a transport.Conn into a vxlan.Port.
type connPort struct{ conn transport.Conn }

func (p *connPort) SendFrame(frame []byte) error { return p.conn.WritePacket(frame) }

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
	clientListeners := make(map[string]transport.Listener)

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
		if len(cfg.ClientListeners) == 0 {
			cancel()
			return nil, fmt.Errorf("no client listeners configured")
		}
		for _, spec := range cfg.ClientListeners {
			if _, dup := clientListeners[spec.Transport]; dup {
				cancel()
				return nil, fmt.Errorf("duplicate listener transport %q", spec.Transport)
			}
			ln, err := createClientListener(spec.Transport, spec.Addr, resolver, configFn)
			if err != nil {
				cancel()
				for _, existing := range clientListeners {
					_ = existing.Close()
				}
				return nil, fmt.Errorf("listener %s/%s: %w", spec.Transport, spec.Addr, err)
			}
			clientListeners[spec.Transport] = ln
		}
	}

	op := &Operator{
		ctx:             ctx,
		cancel:          cancel,
		log:             logger,
		clientListeners: clientListeners,
		clients:         NewClientTable(),
		Stats:           stats.New(cfg.StatsAddr),
		VNetPools:       pools,
	}

	ctrlCfg := &ctrl.Config{
		UUID:          cfg.UUID,
		ListenAddr:    cfg.OpListenAddr,
		ExternalAddr:  cfg.OpExternalAddr,
		DiscoverAddrs: cfg.DiscoverAddrs,
		Log:           logger,
	}

	// Hook ctrl events into the VXLAN plane:
	//   SessionSync(vmac on opUUID @ ip)  → seed plane MAC table with peer's UDPAddr
	//   SessionRevoke(...)                → forget the remote MAC entry
	ctrlCfg.OnSessionSync = func(vni common.VNI, opUUID [16]byte, vmac common.VMAC, ip netip.Addr) {
		if pools != nil {
			if pool, ok := pools.Get(vni); ok {
				pool.ReserveIP(ip)
			}
		}
		if op.plane == nil || opUUID == op.Ctrl.UUID() {
			return
		}
		if peer, ok := op.Ctrl.Peers.Get(opUUID); ok && peer.UDPAddrPort.IsValid() {
			op.plane.Table().LearnRemote(vni, vmac, peer.UDPAddrPort)
		}
	}
	ctrlCfg.OnSessionRevoke = func(vni common.VNI, _ [16]byte, _ [16]byte, vmac common.VMAC, ip netip.Addr) {
		if pools != nil {
			if pool, ok := pools.Get(vni); ok {
				pool.UnreserveIP(ip)
			}
		}
		if op.plane != nil {
			op.plane.Table().ForgetRemote(vni, vmac)
		}
	}
	op.Ctrl = ctrl.New(ctrlCfg)

	return op, nil
}

func (o *Operator) UUID() [16]byte   { return o.Ctrl.UUID() }
func (o *Operator) GRPCAddr() string { return o.Ctrl.GRPCAddr() }

// ClientAddr returns the bind address of a single arbitrary client listener,
// or "" if none. Retained for tests/inspection; prefer ClientListeners() when
// more than one transport may be active.
func (o *Operator) ClientAddr() string {
	for _, ln := range o.clientListeners {
		return ln.Addr()
	}
	return ""
}

// ClientAddrFor returns the bind address for a specific transport kind.
func (o *Operator) ClientAddrFor(transport string) string {
	if ln, ok := o.clientListeners[transport]; ok {
		return ln.Addr()
	}
	return ""
}

// ClientListeners returns a snapshot of (transport → bind addr).
func (o *Operator) ClientListeners() map[string]string {
	out := make(map[string]string, len(o.clientListeners))
	for t, ln := range o.clientListeners {
		out[t] = ln.Addr()
	}
	return out
}
func (o *Operator) ConnectedClients() int   { return o.clients.Len() }
func (o *Operator) ConnectedOperators() int { return o.Ctrl.Peers.Len() }

// Plane exposes the underlying VXLAN data plane (for tests/inspection).
func (o *Operator) Plane() *vxlan.Plane { return o.plane }

func (o *Operator) Start() error {
	if err := o.Ctrl.Start(); err != nil {
		return err
	}

	// UDP data plane bound on the same {host,port} as gRPC. TCP and UDP
	// coexist on the same port (independent transport tables in the kernel).
	if grpcAddr := o.Ctrl.GRPCAddr(); grpcAddr != "" {
		udpAddr, err := net.ResolveUDPAddr("udp", grpcAddr)
		if err != nil {
			return fmt.Errorf("data plane resolve %s: %w", grpcAddr, err)
		}
		dp, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return fmt.Errorf("data plane listen on %s: %w", grpcAddr, err)
		}
		o.dataPort = dp
		o.plane = vxlan.New(dp)
		o.plane.Start() // RxLoop: decap + Forward + remote MAC learning
		o.log.Infof("VXLAN plane bound to %s", dp.LocalAddr())
	}

	for tp, ln := range o.clientListeners {
		o.log.Infof("Client endpoint (%s) listening on %s", tp, ln.Addr())
		go o.routineAcceptClients(tp, ln)
	}

	go o.routineReaper()

	if err := o.Stats.Start(); err != nil {
		return fmt.Errorf("stats: %w", err)
	}
	return nil
}

func (o *Operator) Close() error {
	o.cancel()
	o.Ctrl.Stop()
	if o.plane != nil {
		o.plane.Close()
	}
	// dataPort is closed by plane.Close() above; nothing to do here.
	o.dataPort = nil
	for _, ln := range o.clientListeners {
		_ = ln.Close()
	}
	o.clients.CloseAll()
	o.Stats.Close()
	return nil
}

// --------------- Client data plane ---------------

func (o *Operator) routineAcceptClients(tp string, ln transport.Listener) {
	for {
		conn, result, err := ln.Accept()
		if err != nil {
			select {
			case <-o.ctx.Done():
				return
			default:
				o.log.Errorf("Client accept failed (%s): %v", tp, err)
				continue
			}
		}
		if conn == nil || result == nil {
			return
		}

		cp := &ClientPeer{
			Conn:       conn,
			SessionID:  result.Config.SessionID,
			VMAC:       result.VMAC,
			VNI:        result.Config.VNI,
			OperatorID: o.Ctrl.UUID(),
			IP:         result.Config.IPPrefix,
			AllowedIPs: result.Config.AllowedRanges,
		}

		o.clients.Add(cp)
		// Register the client conn as a Port on the VXLAN plane.
		if o.plane != nil {
			o.plane.RegisterPort(cp.VNI, cp.VMAC, &connPort{conn: cp.Conn})
		}
		o.Stats.Recorder.Register(cp.SessionID, cp.VNI, "", conn.RemoteAddr())
		o.Ctrl.BroadcastSessionSync(cp.SessionID, cp.VNI, cp.VMAC, cp.IP.Addr())

		o.log.Infof("Client %x connected, assigned %s from %s",
			result.VMAC, result.Config.IPPrefix, conn.RemoteAddr())
		go o.routineReadFromClient(cp)
	}
}

// routineReadFromClient reads Eth frames from the client and hands them to
// the VXLAN plane for forwarding. The plane decides local-port delivery,
// remote-operator VXLAN encap, or broadcast flood.
func (o *Operator) routineReadFromClient(cp *ClientPeer) {
	defer func() {
		o.clients.Remove(cp)
		if o.plane != nil {
			o.plane.UnregisterPort(cp.VNI, cp.VMAC)
		}
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
		if n < common.EthHeaderSize {
			continue
		}
		if n > common.MaxVxlanPayload {
			o.log.Warnf("Client %x oversize frame %d > %d, dropping", cp.SessionID, n, common.MaxVxlanPayload)
			continue
		}

		o.Stats.Recorder.RecordRx(cp.SessionID, uint64(n))
		if !o.Stats.RateLimiter.Allow(cp.VNI, uint64(n)) {
			continue
		}

		// Keepalive interception: a frame with dst=all-zero and
		// EtherType=0x88B5 never enters the VXLAN plane. Reply in place
		// with (dst=clientMAC, src=all-zero, type=0x88B5).
		if src, ok := common.IsKeepaliveRequest(readBuf[:n]); ok {
			if src == cp.VMAC {
				df := common.BuildKeepaliveReply(cp.VMAC)
				if err := cp.Conn.WritePacket(df.Bytes()); err != nil {
					o.log.Debugf("keepalive reply to %x: %v", cp.VMAC, err)
				}
				common.PutFrame(df)
			}
			continue
		}

		if o.plane != nil {
			_ = o.plane.Forward(cp.VNI, readBuf[:n])
		}
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
		var stale []*ClientPeer
		for _, cp := range o.clients.Snapshot() {
			if now.Sub(cp.Conn.LastActive()) > idleTimeout {
				stale = append(stale, cp)
			}
		}
		for _, cp := range stale {
			idle := now.Sub(cp.Conn.LastActive())
			o.log.Warnf("Reaping idle client %x (idle %v)", cp.SessionID, idle.Round(time.Second))
			cp.Conn.Close()
		}
	}
}

// --------------- Helpers ---------------

func makeConfigFunc(pools *VNetPoolMap, serverPub encryption.PublicKey) protocol.ConfigFunc {
	return func(vmac common.VMAC, vni common.VNI) (*protocol.SessionConfig, error) {
		pool, ok := pools.Get(vni)
		if !ok {
			return nil, fmt.Errorf("unknown vni %s", vni)
		}
		// Generate sessionID BEFORE allocating IP — IPv6 derivation needs it.
		h := sha256.New()
		h.Write(vmac[:])
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
