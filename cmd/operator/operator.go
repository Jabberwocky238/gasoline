package operator

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/jabberwocky238/gasoline/cmd/operator/stats"
	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/device/vxlan"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport"
	transportQuic "github.com/jabberwocky238/gasoline/transport/quic"
	transportTcp "github.com/jabberwocky238/gasoline/transport/tcp"
	transportTls "github.com/jabberwocky238/gasoline/transport/tls"
	transportUdp "github.com/jabberwocky238/gasoline/transport/udp"
)

// Operator is the per-process control + data plane orchestrator.
type Operator struct {
	ctx    context.Context
	cancel context.CancelFunc
	cfg    *StaticOperatorConfig

	log  *log.Logger
	uuid [16]byte

	clientListeners map[string]transport.Listener

	state *operatorState
}

func New(cfg *StaticOperatorConfig) (*Operator, error) {
	logger := log.New()
	logger.SetLevel(cfg.LogLevel)

	ctx, cancel := context.WithCancel(context.Background())
	clientListeners := make(map[string]transport.Listener)

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

	resolver = auth.NewMapResolver()
	for vni, authStr := range cfg.NetworkAuth {
		vnetAuth, err := auth.ParseServerAuth(authStr)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("auth for vni %s: %w", vni, err)
		}
		resolver.Set(vni, vnetAuth)
	}

	if len(cfg.ClientListeners) == 0 {
		cancel()
		return nil, fmt.Errorf("no client listeners configured")
	}
	for _, spec := range cfg.ClientListeners {
		if _, dup := clientListeners[spec.Transport]; dup {
			cancel()
			return nil, fmt.Errorf("duplicate listener transport %q", spec.Transport)
		}
		ln, err := createClientListener(spec.Transport, spec.Addr, resolver)
		if err != nil {
			cancel()
			for _, existing := range clientListeners {
				_ = existing.Close()
			}
			return nil, fmt.Errorf("listener %s/%s: %w", spec.Transport, spec.Addr, err)
		}
		clientListeners[spec.Transport] = ln
	}

	var uuid [16]byte
	if cfg.UUID != nil {
		uuid = *cfg.UUID
	} else {
		rand.Read(uuid[:])
	}

	return &Operator{
		ctx:              ctx,
		cancel:           cancel,
		gctx:             gctx,
		log:              logger,
		uuid:             uuid,
		dataListenAddr:   cfg.OpListenAddr,
		dataExternalAddr: cfg.OpExternalAddr,
		Peers:            NewPeerTable(),
		clientListeners:  clientListeners,
		Stats:            stats.New(cfg.StatsAddr),
		VNetPools:        pools,
		authResolver:     resolver,
	}, nil
}

// --------------- Identity / accessors ---------------

func (o *Operator) UUID() [16]byte              { return o.uuid }
func (o *Operator) ExternalAddr() string        { return o.dataExternalAddr }
func (o *Operator) SetExternalAddr(addr string) { o.dataExternalAddr = addr }

func (o *Operator) DataPlaneAddr() string {
	if o.vxlanDev == nil {
		return ""
	}
	if a := o.vxlanDev.LocalAddr(); a != nil {
		return a.String()
	}
	return ""
}

// ClientAddr returns the first client listener's bound address, or
// the empty string if no listener was configured. Useful for tests
// that just want one endpoint to dial.
func (o *Operator) ClientAddr() string {
	for _, ln := range o.clientListeners {
		return ln.Addr()
	}
	return ""
}

// State exposes the per-VNI data-plane registry (vtep, vxlan port,
// clients). Returns nil if Start has not yet built it.
func (o *Operator) State() *operatorState   { return o.state }
func (o *Operator) ConnectedClients() int   { return o.state.TotalClients() }
func (o *Operator) ConnectedOperators() int { return o.Peers.Len() }

// AddPeer registers a peer operator and seeds its underlay address
// into every existing VNI's vxlan port so subsequent BUM traffic
// reaches it.
func (o *Operator) AddPeer(uuid [16]byte, udpAddr netip.AddrPort) {
	if uuid == o.uuid {
		return
	}
	o.Peers.Add(NewPeer(uuid, udpAddr))
	if o.state != nil {
		o.state.SeedAllPeers(udpAddr)
	}
}

// RemovePeer un-registers a peer operator and removes its underlay
// address from every VNI's vxlan port.
func (o *Operator) RemovePeer(uuid [16]byte) {
	if p, ok := o.Peers.Get(uuid); ok && o.state != nil {
		o.state.UnseedAllPeers(p.UDPAddr)
	}
	o.Peers.Remove(uuid)
}

// --------------- Hot reload ---------------

func (o *Operator) RegisterReloader(name string, builder HotReloaderBuilder) error {
	if builder == nil {
		return fmt.Errorf("operator: nil HotReloaderBuilder for %q", name)
	}
	r, err := builder(o.VNetPools, o.authResolver, o.log)
	if err != nil {
		return err
	}
	if r == nil {
		return fmt.Errorf("operator: builder for %q returned nil reloader", name)
	}
	if o.Reloaders == nil {
		o.Reloaders = make(map[string]HotReloader)
	}
	if old, ok := o.Reloaders[name]; ok && old != nil {
		_ = old.Close()
	}
	o.Reloaders[name] = r
	return nil
}

// --------------- Lifecycle ---------------

func (o *Operator) Start() error {
	if o.dataListenAddr != "" {
		udpAddr, err := net.ResolveUDPAddr("udp", o.dataListenAddr)
		if err != nil {
			return fmt.Errorf("data plane resolve %s: %w", o.dataListenAddr, err)
		}
		dp, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return fmt.Errorf("data plane listen on %s: %w", o.dataListenAddr, err)
		}
		// vxlan.Device takes ownership of dp — its Close() closes the
		// socket; the operator no longer carries a back-reference.
		o.vxlanDev = vxlan.New(o.gctx, dp)
		o.vxlanDev.Start()
		o.log.Infof("VXLAN underlay bound to %s", dp.LocalAddr())
	}

	o.state = newOperatorState(o.gctx, o.vxlanDev)

	// Seed any peers already registered before Start.
	for _, p := range o.Peers.All() {
		o.state.SeedAllPeers(p.UDPAddr)
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
	for _, r := range o.Reloaders {
		if r != nil {
			_ = r.Close()
		}
	}
	o.Reloaders = nil

	for _, ln := range o.clientListeners {
		_ = ln.Close()
	}
	if o.state != nil {
		o.state.CloseAll()
	}
	if o.vxlanDev != nil {
		_ = o.vxlanDev.Close() // also closes the underlying UDP socket
	}
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

		cp := &PeerClient{
			Conn:       conn,
			SessionID:  result.Config.SessionID,
			VNI:        result.Config.VNI,
			IP:         result.Config.IPPrefix,
			AllowedIPs: result.Config.AllowedRanges,
		}

		vn, err := o.state.AddClient(cp, cp)
		if err != nil {
			o.log.Errorf("attach client %x to VNI %s: %v", cp.VMAC, cp.VNI, err)
			_ = conn.Close()
			continue
		}

		// Seed FDBs — local first (so this operator immediately knows
		// the new client's port) then fan out to peer operators so
		// they record cp.VMAC → vxlan port. Frame uses the FDB-only
		// EtherType so neither side actually delivers it anywhere.
		announce := buildAnnounceFrame(cp.VMAC)
		_ = vn.vtep.DeliverL2(cp.ID(), announce, nil)
		if vn.vxlanPort != nil {
			if err := vn.vxlanPort.SendFrame(common.EthBroadcastMAC, announce); err != nil {
				o.log.Debugf("announce client %x to peers: %v", cp.VMAC, err)
			}
		}

		o.Stats.Recorder.Register(cp.SessionID, cp.VNI, "", conn.RemoteAddr())

		o.log.Infof("Client %x connected, assigned %s from %s",
			result.VMAC, result.Config.IPPrefix, conn.RemoteAddr())
		go o.routineReadFromClient(cp, vn, cp.ID())
	}
}

func (o *Operator) routineReadFromClient(cp *PeerClient, vn *vniEntry, portID string) {
	defer func() {
		o.state.RemoveClient(cp, portID)
		o.Stats.Recorder.Unregister(cp.SessionID)
		_ = cp.Conn.Close()
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
		if n > vxlan.MaxVxlanPayload {
			o.log.Warnf("Client %x oversize frame %d > %d, dropping", cp.SessionID, n, vxlan.MaxVxlanPayload)
			continue
		}

		o.Stats.Recorder.RecordRx(cp.SessionID, uint64(n))
		if !o.Stats.RateLimiter.Allow(cp.VNI, uint64(n)) {
			continue
		}

		// Operator-side keepalive intercept: never reaches the data
		// plane, just reflects back to the client.
		if src, ok := common.IsKeepaliveRequest(readBuf[:n]); ok {
			if src == cp.VMAC {
				if err := cp.Conn.WritePacket(common.BuildKeepaliveReply(cp.VMAC)); err != nil {
					o.log.Debugf("keepalive reply to %x: %v", cp.VMAC, err)
				}
			}
			continue
		}

		if err := vn.vtep.DeliverL2(portID, readBuf[:n], nil); err != nil {
			o.log.Debugf("client %x → vtep %s: %v", cp.SessionID, cp.VNI, err)
		}
	}
}

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
		var stale []*PeerClient
		for _, cp := range o.state.Snapshot() {
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

// --------------- Client listener helpers ---------------

func createClientListener(transportType, addr string, resolver auth.AuthResolver) (transport.Listener, error) {
	switch transportType {
	case "tcp":
		return transportTcp.NewListener(addr, resolver)
	case "udp":
		return transportUdp.NewListener(addr, resolver)
	case "quic":
		tlsConf, err := transportQuic.GenerateServerTLS()
		if err != nil {
			return nil, err
		}
		return transportQuic.NewListener(addr, resolver, tlsConf)
	case "tls":
		tlsConf, err := transportQuic.GenerateServerTLS()
		if err != nil {
			return nil, err
		}
		return transportTls.NewListener(addr, resolver, tlsConf)
	default:
		return nil, fmt.Errorf("unknown transport: %s", transportType)
	}
}
