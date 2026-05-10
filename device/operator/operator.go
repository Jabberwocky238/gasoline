package operator

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
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

// MessageTransport header layout repeated here for the receive parser
// (the message package owns the encode side).
const (
	msgHeaderSize = 12
	msgVNIOff     = 0
	msgPayOff     = 12
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
	dataConn        *net.UDPConn // underlay socket, shared by all peers
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

// AddPeer registers a remote operator and stamps the local underlay
// send socket onto it so forwardFrame can ship MessageTransport bytes
// straight to the peer's UDPAddr.
func (o *Operator) AddPeer(uuid [16]byte, udpAddr netip.AddrPort) {
	if uuid == o.uuid {
		return
	}
	p := NewPeerOperator(uuid, udpAddr)
	if o.dataConn != nil {
		p.SetSendSocket(o.dataConn)
	}
	o.state.Peers.Add(p)
}

// DataPlaneAddr returns the bound underlay UDP address ("host:port")
// or "" if the underlay isn't running.
func (o *Operator) DataPlaneAddr() string {
	if o.dataConn == nil {
		return ""
	}
	return o.dataConn.LocalAddr().String()
}

// SetPeerRoute installs (vni, prefix) -> peer operator UUID into the
// VNI's routing table. Called either at boot from a static config or
// at runtime when the coordinator pushes a remote-owned route.
func (o *Operator) SetPeerRoute(vni protocol.VNI_Ty, peerUUID [16]byte, prefix netip.Prefix) error {
	vn, ok := o.state.vni(vni)
	if !ok {
		return fmt.Errorf("unknown vni %d", vni)
	}
	vn.routingMap.SetOperator(peerUUID, prefix)
	return nil
}

func (o *Operator) RemovePeer(uuid [16]byte) {
	o.state.Peers.Remove(uuid)
}

// --------------- Lifecycle ---------------

func (o *Operator) Start() error {
	if o.dataListenAddr != "" {
		udpAddr, err := net.ResolveUDPAddr("udp", o.dataListenAddr)
		if err != nil {
			return fmt.Errorf("data plane resolve %s: %w", o.dataListenAddr, err)
		}
		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return fmt.Errorf("data plane listen on %s: %w", o.dataListenAddr, err)
		}
		o.dataConn = conn
		o.lctx.Log().Infof("Underlay UDP listening on %s", conn.LocalAddr())
		// Stamp every existing peer with the new socket.
		for _, p := range o.state.Peers.All() {
			p.SetSendSocket(conn)
		}
		go o.routineReadFromPeer()
	}
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
	if o.dataConn != nil {
		_ = o.dataConn.Close()
		o.dataConn = nil
	}
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

// routineReadFromPeer drains the underlay UDP socket. Each datagram is
// a MessageTransport (vni|cid|payload). The vni picks the local
// vniEntry; vniEntry.deliverFromPeer hands the payload to the local
// client that owns the destination IP.
func (o *Operator) routineReadFromPeer() {
	logger := o.lctx.Log()
	conn := o.dataConn
	if conn == nil {
		return
	}
	buf := make([]byte, common.MaxPacketSize)
	for {
		select {
		case <-o.lctx.Done():
			return
		default:
		}
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-o.lctx.Done():
				return
			default:
				logger.Debugf("peer read: %v", err)
				continue
			}
		}
		if n < msgHeaderSize {
			continue
		}
		vni := protocol.VNI_Ty(binary.BigEndian.Uint32(buf[msgVNIOff : msgVNIOff+4]))
		payload := buf[msgPayOff:n]
		vn, ok := o.state.vni(vni)
		if !ok {
			continue
		}
		if err := vn.deliverFromPeer(payload); err != nil {
			logger.Debugf("deliver vni %d from peer: %v", vni, err)
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
