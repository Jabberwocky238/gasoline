package operator

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"github.com/jabberwocky238/gasoline/cmd/operator/device/consensus"
	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/assign"
	"github.com/jabberwocky238/gasoline/protocol/dataframe"
	"github.com/jabberwocky238/gasoline/protocol/handshake"
	"github.com/jabberwocky238/gasoline/protocol/noise"
	"github.com/jabberwocky238/gasoline/transport"
	_ "github.com/jabberwocky238/gasoline/transport/quic" // self-registers
	transportQuic "github.com/jabberwocky238/gasoline/transport/quic"
	_ "github.com/jabberwocky238/gasoline/transport/udp" // self-registers
	log "github.com/sirupsen/logrus"
)

// MessageTransport header layout for the receive parser (the message
// package owns the encode side).
const (
	msgHeaderSize = 12
	msgVNIOff     = 0
	msgPayOff     = 12
)

// Operator is the per-process control + data plane orchestrator.
type Operator struct {
	lctx *common.LogContext
	cfg  *StaticOperatorConfig

	uuid [16]byte

	dataListenAddr  string
	clientListeners map[string]transport.Listener
	state           *operatorState
}

// vniResolver is the per-VNI handshake.VNIResolver implementation backed by an
// operator's vniEntry. It is AUTH-ONLY: operator key pair + authorization
// check. IP assignment is not here — see localAllocator / package assign.
type vniResolver struct {
	vn         *vniEntry
	staticPriv noise.PrivateKey
	staticPub  noise.PublicKey
}

func (r *vniResolver) ServerStatic() (noise.PrivateKey, noise.PublicKey) {
	return r.staticPriv, r.staticPub
}
func (r *vniResolver) Authorized(pubkey noise.PublicKey) bool { return r.vn.authorized(pubkey) }

func New(cfg *StaticOperatorConfig) (*Operator, error) {
	logger := log.New()
	logger.SetLevel(cfg.LogLevel)
	root := common.NewLogContext(context.Background(), logger)

	state := newOperatorState(root)

	// Operator static key pair (Noise responder identity). Generate one if the
	// config supplied none; its public key is conveyed to clients out of band.
	var zeroPriv noise.PrivateKey
	if cfg.StaticPriv == zeroPriv {
		priv, pub, err := noise.GenerateKey()
		if err != nil {
			root.Cancel()
			return nil, fmt.Errorf("generate operator static key: %w", err)
		}
		state.staticPriv, state.staticPub = priv, pub
	} else {
		state.staticPriv = cfg.StaticPriv
		state.staticPub = cfg.StaticPriv.Public()
	}

	// VNI registration + preset routes.
	state.cidrs = make(map[protocol.VNI_Ty]netip.Prefix)
	for vni, entry := range cfg.Network {
		prefix, err := netip.ParsePrefix(entry.CIDR)
		if err != nil {
			root.Cancel()
			return nil, fmt.Errorf("vni %s cidr %q: %w", vni, entry.CIDR, err)
		}
		state.cidrs[vni] = prefix
		state.registerVNI(vni, entry.AuthorizedKeys)
		if len(entry.PresetKeyMap) > 0 {
			vn, _ := state.vni(vni)
			vn.presetIP = entry.PresetKeyMap
		}
		root.Log().Infof("VNet %s: %s (%d preset keys)", vni, prefix, len(entry.PresetKeyMap))
	}

	// One mapper closure shared by every listener. The resolver is auth-only:
	// operator key pair + authorization check. IP assignment is the allocator's
	// job, run after the handshake.
	mapper := func(vni protocol.VNI_Ty) (handshake.VNIResolver, error) {
		state.mu.RLock()
		vn, ok := state.vnets[vni]
		state.mu.RUnlock()
		if !ok {
			return nil, fmt.Errorf("no config for vni %s", vni)
		}
		return &vniResolver{vn: vn, staticPriv: state.staticPriv, staticPub: state.staticPub}, nil
	}

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
		tlsConf, err := transportQuic.GenerateServerTLS()
		if err != nil {
			return nil, err
		}
		ln, err := transport.NewListener(spec.Transport, spec.Addr, mapper, tlsConf)
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
	state.uuid = uuid

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

func (o *Operator) UUID() [16]byte { return o.uuid }

// StaticPub returns the operator's Noise static public key. Clients need it
// (out of band) to run the IK handshake against this operator.
func (o *Operator) StaticPub() noise.PublicKey { return o.state.staticPub }

// allocator selects the assign backend: Raft-backed when a consensus node is
// attached, else the pre-consensus preset allocator.
func (o *Operator) allocator() assign.Allocator {
	if o.state.node != nil {
		return &raftAllocator{
			node:     o.state.node,
			state:    o.state,
			leaseTTL: 3600 * time.Second,
			self:     o.uuid,
			timeout:  5 * time.Second,
		}
	}
	return &localAllocator{state: o.state}
}

// AttachConsensus wires a running consensus node so IP/SessionID allocation
// commits through Raft. Call before Start.
func (o *Operator) AttachConsensus(node *consensus.Node) { o.state.node = node }
func (o *Operator) ConnectedClients() int                { return o.state.totalClients() }
func (o *Operator) State() *operatorState                { return o.state }

// ClientAddr returns the first client listener's bound address, or
// the empty string if no listener was configured.
func (o *Operator) ClientAddr() string {
	for _, ln := range o.clientListeners {
		return ln.Addr()
	}
	return ""
}

// AddPeer registers a remote operator. PeerTable.Add stamps the
// shared underlay send socket onto it automatically.
func (o *Operator) AddPeer(uuid [16]byte, udpAddr netip.AddrPort) {
	if uuid == o.uuid {
		return
	}
	o.state.Peers.Add(NewPeerOperator(uuid, udpAddr))
}

// DataPlaneAddr returns the bound underlay UDP address ("host:port")
// or "" if the underlay isn't running.
func (o *Operator) DataPlaneAddr() string { return o.state.Peers.Addr() }

// SetPeerRoute installs (vni, prefix) -> peer operator UUID into the
// VNI's routing table.
func (o *Operator) SetPeerRoute(vni protocol.VNI_Ty, peerUUID [16]byte, prefix netip.Prefix) error {
	vn, ok := o.state.vni(vni)
	if !ok {
		return fmt.Errorf("unknown vni %s", vni)
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
		conn, err := o.state.Peers.Bind(o.dataListenAddr)
		if err != nil {
			return err
		}
		o.lctx.Log().Infof("Underlay UDP listening on %s", conn.LocalAddr())
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
	if o.state != nil {
		_ = o.state.Peers.Close()
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

		acc, err := ln.Accept()
		if err != nil {
			select {
			case <-o.lctx.Done():
				return
			default:
				logger.Errorf("Client accept failed (%s): %v", tp, err)
				continue
			}
		}
		if acc.Conn == nil {
			return
		}

		// Authentication is done (acc carries the identity + Session). Run the
		// control-plane assignment (preclaim/claim/ack/confirm) to get an IP +
		// SessionID. Use the Raft-backed allocator when consensus is running,
		// otherwise the pre-consensus preset allocator.
		alloc := o.allocator()
		keys := assign.DataKeys{C2SKey: acc.C2SKey, S2CKey: acc.S2CKey}
		sc, err := assign.ServerAssign(acc.Conn, acc.Session, acc.VNI, acc.ClientPub, o.state.nextSessionIndex(), keys, alloc)
		if err != nil {
			logger.Errorf("assign on VNI %s: %v", acc.VNI, err)
			_ = acc.Conn.Close()
			continue
		}

		cp := newPeerClient(acc.Conn, sc, acc.Session)
		vn, err := o.state.addClient(cp)
		if err != nil {
			logger.Errorf("attach cid %s sessionindex %d to VNI %s: %v", cp.sc.SessionID, cp.sc.SessionIndex, cp.sc.VNI, err)
			_ = acc.Conn.Close()
			continue
		}

		logger.Infof("cid %s sessionindex %d connected on VNI %s from %s",
			cp.sc.SessionID, cp.sc.SessionIndex, cp.sc.VNI, acc.Conn.RemoteAddr())
		go o.routineReadFromClient(cp, vn)
	}
}

func (o *Operator) routineReadFromClient(cp *PeerClient, vn *vniEntry) {
	logger := o.lctx.Log()
	defer func() {
		o.state.removeClient(cp)
		_ = cp.Conn.Close()
		cp.closed.Store(true)
		logger.Infof("cid %s sessionindex %d disconnected", cp.sc.SessionID, cp.sc.SessionIndex)
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
			logger.Debugf("Read from cid %s sessionindex %d: %v", cp.sc.SessionID, cp.sc.SessionIndex, err)
			return
		}
		if n == 0 {
			continue
		}

		// Decrypt the data frame using this conn's session (the client handshook
		// here). Forwarding then works on the plaintext IP packet and re-seals
		// per destination.
		_, ctr, ct, err := dataframe.ParseHeader(readBuf[:n])
		if err != nil {
			logger.Debugf("parse frame from sessionindex %d: %v", cp.sc.SessionIndex, err)
			continue
		}
		pt, err := dataframe.Open(cp.session, ctr, ct, true)
		if err != nil {
			logger.Debugf("open frame from sessionindex %d: %v", cp.sc.SessionIndex, err)
			continue
		}

		if err := vn.forwardFrame(pt, cp); err != nil {
			logger.Debugf("Forward from cid %s sessionindex %d: %v", cp.sc.SessionID, cp.sc.SessionIndex, err)
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
				logger.Warnf("Reaping idle cid %s sessionindex %d", cp.sc.SessionID, cp.sc.SessionIndex)
				_ = cp.Conn.Close()
			}
		}
	}
}

// routineReadFromPeer drains the underlay UDP socket. Each datagram is
// a MessageTransport (vni|cid|payload).
func (o *Operator) routineReadFromPeer() {
	logger := o.lctx.Log()
	conn := o.state.Peers.Conn()
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
			logger.Debugf("deliver vni %s from peer: %v", vni, err)
		}
	}
}
