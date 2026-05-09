package operator

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net/netip"
	"time"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
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
	ctx    context.Context
	cancel context.CancelFunc
	cfg    *StaticOperatorConfig

	log  *log.Logger
	uuid [16]byte

	dataListenAddr  string
	clientListeners map[string]transport.Listener
	authResolver    *staticAuthResolver

	state *operatorState
}

// staticAuthResolver resolves per-VNI auth from a fixed map.
type staticAuthResolver struct {
	byVNI map[protocol.VNI_Ty]auth.ServerAuthenticator
}

func (r *staticAuthResolver) Resolve(vni protocol.VNI_Ty) (auth.ServerAuthenticator, error) {
	a, ok := r.byVNI[vni]
	if !ok {
		return nil, fmt.Errorf("no auth registered for vni %d", vni)
	}
	return a, nil
}

func New(cfg *StaticOperatorConfig) (*Operator, error) {
	logger := log.New()
	logger.SetLevel(cfg.LogLevel)

	ctx, cancel := context.WithCancel(context.Background())

	resolver := &staticAuthResolver{byVNI: make(map[protocol.VNI_Ty]auth.ServerAuthenticator)}
	for vni, entry := range cfg.Network {
		if entry.Auth != nil {
			resolver.byVNI[vni] = entry.Auth
		}
	}

	if len(cfg.ClientListeners) == 0 {
		cancel()
		return nil, fmt.Errorf("no client listeners configured")
	}
	clientListeners := make(map[string]transport.Listener)
	for _, spec := range cfg.ClientListeners {
		if _, dup := clientListeners[spec.Transport]; dup {
			cancel()
			closeAll(clientListeners)
			return nil, fmt.Errorf("duplicate listener transport %q", spec.Transport)
		}
		ln, err := createClientListener(spec.Transport, spec.Addr, resolver)
		if err != nil {
			cancel()
			closeAll(clientListeners)
			return nil, fmt.Errorf("listener %s/%s: %w", spec.Transport, spec.Addr, err)
		}
		clientListeners[spec.Transport] = ln
	}

	state := newOperatorState(ctx)

	seedBig, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
	seed := uint32(seedBig.Int64())
	for vni, entry := range cfg.Network {
		prefix, err := netip.ParsePrefix(entry.CIDR)
		if err != nil {
			cancel()
			closeAll(clientListeners)
			return nil, fmt.Errorf("vni %d cidr %q: %w", vni, entry.CIDR, err)
		}
		pool := NewVNetPool(prefix, seed)
		pool.VNI = vni
		state.registerVNI(vni, entry.Auth, pool)
		logger.Infof("VNet %d: %s", vni, prefix)
	}

	var uuid [16]byte
	if cfg.UUID != nil {
		uuid = *cfg.UUID
	} else {
		_, _ = rand.Read(uuid[:])
	}

	return &Operator{
		ctx:             ctx,
		cancel:          cancel,
		cfg:             cfg,
		log:             logger,
		uuid:            uuid,
		dataListenAddr:  cfg.OpListenAddr,
		clientListeners: clientListeners,
		authResolver:    resolver,
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
	o.state.Peers.Add(NewPeer(uuid, udpAddr))
}

func (o *Operator) RemovePeer(uuid [16]byte) {
	o.state.Peers.Remove(uuid)
}

// --------------- Lifecycle ---------------

func (o *Operator) Start() error {
	for tp, ln := range o.clientListeners {
		o.log.Infof("Client endpoint (%s) listening on %s", tp, ln.Addr())
		go o.routineAcceptClients(tp, ln)
	}
	go o.routineReaper()
	return nil
}

func (o *Operator) Close() error {
	o.cancel()
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
	for {
		select {
		case <-o.ctx.Done():
			return
		default:
		}

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

		cp := newPeerClient(conn, result)
		vn, err := o.state.addClient(cp)
		if err != nil {
			o.log.Errorf("attach client %d to VNI %d: %v", cp.SessionIndex, cp.VNI, err)
			_ = conn.Close()
			continue
		}

		o.log.Infof("Client %d connected on VNI %d from %s",
			cp.SessionIndex, cp.VNI, conn.RemoteAddr())
		go o.routineReadFromClient(cp, vn)
	}
}

func (o *Operator) routineReadFromClient(cp *PeerClient, vn *vniEntry) {
	defer func() {
		o.state.removeClient(cp)
		_ = cp.Conn.Close()
		cp.closed.Store(true)
		o.log.Infof("Client %d disconnected", cp.SessionIndex)
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
			o.log.Debugf("Read from client %d: %v", cp.SessionIndex, err)
			return
		}
		if n == 0 {
			continue
		}

		// Per-VNI L2 broadcast: forward this frame to every other client
		// in the same VNI. No FDB / no underlay until those subsystems
		// come back.
		frame := append([]byte(nil), readBuf[:n]...)
		for _, other := range vn.peers(cp.SessionIndex) {
			if other.closed.Load() {
				continue
			}
			if err := other.Conn.WritePacket(frame); err != nil {
				o.log.Debugf("forward to client %d: %v", other.SessionIndex, err)
			}
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
		for _, cp := range o.state.snapshot() {
			if now.Sub(cp.Conn.LastActive()) > idleTimeout {
				o.log.Warnf("Reaping idle client %d", cp.SessionIndex)
				_ = cp.Conn.Close()
			}
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
