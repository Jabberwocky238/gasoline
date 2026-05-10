package operator

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/netip"
	"time"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/protocol/handshake"
	"github.com/jabberwocky238/gasoline/transport"
	transportQuic "github.com/jabberwocky238/gasoline/transport/quic"
	transportTcp "github.com/jabberwocky238/gasoline/transport/tcp"
	transportTls "github.com/jabberwocky238/gasoline/transport/tls"
	transportUdp "github.com/jabberwocky238/gasoline/transport/udp"
	log "github.com/sirupsen/logrus"
)

// Operator is the per-process control + data plane orchestrator.
//
// Without a VXLAN underlay or peer fanout, this implementation only
// forwards frames between clients attached to the same VNI on this
// operator (an L2 broadcast switch per VNI). Inter-operator traffic
// is out of scope until the underlay is brought back.
type Operator struct {
	lctx *common.LogContext
	cfg  *StaticOperatorConfig

	uuid [16]byte

	dataListenAddr  string
	clientListeners map[string]transport.Listener
	state           *operatorState
}

func New(cfg *StaticOperatorConfig) (*Operator, error) {
	logger := log.New()
	logger.SetLevel(cfg.LogLevel)
	root := common.NewLogContext(context.Background(), logger)

	state := newOperatorState(root)
	// init vni config and auth resolver
	for vni, entry := range cfg.Network {
		prefix, err := netip.ParsePrefix(entry.CIDR)
		if err != nil {
			root.Cancel()
			return nil, fmt.Errorf("vni %d cidr %q: %w", vni, entry.CIDR, err)
		}
		state.registerVNI(vni, entry.Auth)
		// Seed preassigned cid->prefix bindings into this VNI's
		// routingMap so handshakes succeed before any coordinator
		// pushes routes.
		if len(entry.PresetCIDmap) > 0 {
			vn, _ := state.vni(vni)
			for cid, pfx := range entry.PresetCIDmap {
				vn.routingMap.Set(cid, pfx)
			}
		}
		root.Log().Infof("VNet %d: %s (%d preset routes)", vni, prefix, len(entry.PresetCIDmap))
	}

	// init client listeners
	if len(cfg.ClientListeners) == 0 {
		root.Cancel()
		return nil, fmt.Errorf("no client listeners configured")
	}
	clientListeners := make(map[string]transport.Listener)
	for _, spec := range cfg.ClientListeners {
		if _, dup := clientListeners[spec.Transport]; dup {
			root.Cancel()
			closeAll(clientListeners)
			return nil, fmt.Errorf("duplicate listener transport %q", spec.Transport)
		}
		authResolver := func(vni protocol.VNI_Ty) (auth.ServerAuthenticator, error) {
			if entry, ok := state.vnets[vni]; ok {
				return entry.authenticator, nil
			}
			return nil, fmt.Errorf("no config for vni %d", vni)
		}
		routeResolver := func(vni protocol.VNI_Ty, cid protocol.CID_Ty) (netip.Prefix, error) {
			entry, ok := state.vnets[vni]
			if !ok {
				return netip.Prefix{}, fmt.Errorf("no config for vni %d", vni)
			}
			pfx, ok := entry.routingMap.LookupByCID(cid)
			if !ok {
				return netip.Prefix{}, fmt.Errorf("no route assigned for cid %x", cid)
			}
			return pfx, nil
		}
		ln, err := createClientListener(spec.Transport, spec.Addr, authResolver, routeResolver)
		if err != nil {
			root.Cancel()
			closeAll(clientListeners)
			return nil, fmt.Errorf("listener %s/%s: %w", spec.Transport, spec.Addr, err)
		}
		clientListeners[spec.Transport] = ln
	}

	var uuid [16]byte
	if cfg.UUID != nil {
		uuid = *cfg.UUID
	} else {
		_, _ = rand.Read(uuid[:])
	}

	return &Operator{
		lctx:            root,
		cfg:             cfg,
		uuid:            uuid,
		dataListenAddr:  cfg.OpListenAddr,
		clientListeners: clientListeners,
		state:           state,
	}, nil
}

// --------------- Identity / accessors ---------------

func (o *Operator) UUID() [16]byte        { return o.uuid }
func (o *Operator) ConnectedClients() int { return o.state.totalClients() }
func (o *Operator) State() *operatorState { return o.state }

// ClientAddr returns the first client listener's bound address, or
// the empty string if no listener was configured.
func (o *Operator) ClientAddr() string {
	for _, ln := range o.clientListeners {
		return ln.Addr()
	}
	return ""
}

// AddPeer registers a remote operator. Without an underlay we just
// record the entry; nothing forwards traffic to it yet.
func (o *Operator) AddPeer(uuid [16]byte, udpAddr netip.AddrPort) {
	if uuid == o.uuid {
		return
	}
	o.state.Peers.Add(NewPeerOperator(uuid, udpAddr))
}

func (o *Operator) RemovePeer(uuid [16]byte) {
	o.state.Peers.Remove(uuid)
}

// --------------- Lifecycle ---------------

func (o *Operator) Start() error {
	for tp, ln := range o.clientListeners {
		o.lctx.Log().Infof("Client endpoint (%s) listening on %s", tp, ln.Addr())
		go o.routineAcceptClients(tp, ln)
	}
	go o.routineReaper()
	return nil
}

func (o *Operator) Close() error {
	o.lctx.Cancel()
	closeAll(o.clientListeners)
	if o.state != nil {
		o.state.closeAll()
	}
	return nil
}

func closeAll(lns map[string]transport.Listener) {
	for _, ln := range lns {
		_ = ln.Close()
	}
}

// --------------- Client data plane ---------------

func (o *Operator) routineAcceptClients(tp string, ln transport.Listener) {
	logger := o.lctx.Log()
	for {
		select {
		case <-o.lctx.Done():
			return
		default:
		}

		conn, result, err := ln.Accept()
		if err != nil {
			select {
			case <-o.lctx.Done():
				return
			default:
				logger.Errorf("Client accept failed (%s): %v", tp, err)
				continue
			}
		}
		if conn == nil || result == nil {
			return
		}

		cp := newPeerClient(conn, result)
		vn, err := o.state.addClient(cp)
		if err != nil {
			logger.Errorf("attach client %d to VNI %d: %v", cp.SessionIndex, cp.VNI, err)
			_ = conn.Close()
			continue
		}

		logger.Infof("Client %d connected on VNI %d from %s",
			cp.SessionIndex, cp.VNI, conn.RemoteAddr())
		go o.routineReadFromClient(cp, vn)
	}
}

func (o *Operator) routineReadFromClient(cp *PeerClient, vn *vniEntry) {
	logger := o.lctx.Log()
	defer func() {
		o.state.removeClient(cp)
		_ = cp.Conn.Close()
		cp.closed.Store(true)
		logger.Infof("Client %d disconnected", cp.SessionIndex)
	}()

	bufPtr := common.GetBuffer()
	defer common.PutBuffer(bufPtr)
	readBuf := *bufPtr

	for {
		select {
		case <-o.lctx.Done():
			return
		default:
		}

		n, err := cp.Conn.ReadPacket(readBuf)
		if err != nil {
			logger.Debugf("Read from client %d: %v", cp.SessionIndex, err)
			return
		}
		if n == 0 {
			continue
		}

		// ip routing
		if err := vn.forwardFrame(readBuf[:n], cp); err != nil {
			logger.Debugf("Forward from client %d: %v", cp.SessionIndex, err)
		}
	}
}

func (o *Operator) routineReaper() {
	logger := o.lctx.Log()
	const idleTimeout = 60 * time.Second
	ticker := time.NewTicker(idleTimeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-o.lctx.Done():
			return
		case <-ticker.C:
		}

		now := time.Now()
		for _, cp := range o.state.snapshot() {
			if now.Sub(cp.Conn.LastActive()) > idleTimeout {
				logger.Warnf("Reaping idle client %d", cp.SessionIndex)
				_ = cp.Conn.Close()
			}
		}
	}
}

// --------------- Client listener helpers ---------------

func createClientListener(transportType, addr string, resolver auth.AuthResolverFn, routes handshake.RouteResolverFn) (transport.Listener, error) {
	switch transportType {
	case "tcp":
		return transportTcp.NewListener(addr, resolver, routes)
	case "udp":
		return transportUdp.NewListener(addr, resolver, routes)
	case "quic":
		tlsConf, err := transportQuic.GenerateServerTLS()
		if err != nil {
			return nil, err
		}
		return transportQuic.NewListener(addr, resolver, routes, tlsConf)
	case "tls":
		tlsConf, err := transportQuic.GenerateServerTLS()
		if err != nil {
			return nil, err
		}
		return transportTls.NewListener(addr, resolver, routes, tlsConf)
	default:
		return nil, fmt.Errorf("unknown transport: %s", transportType)
	}
}
