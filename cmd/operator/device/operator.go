package operator

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/protocol/handshake"
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

// vniResolver is the per-VNI handshake.VNIResolver implementation
// backed by an operator's vniEntry.
type vniResolver struct {
	vn   *vniEntry
	cidr netip.Prefix
}

func (r *vniResolver) CIDR() netip.Prefix                      { return r.cidr }
func (r *vniResolver) Authenticator() auth.ServerAuthenticator { return r.vn.authenticator }
func (r *vniResolver) IP(cid protocol.CID_Ty) (netip.Addr, error) {
	pfx, ok := r.vn.routingMap.LookupByCID(cid)
	if !ok {
		return netip.Addr{}, fmt.Errorf("no route assigned for cid %s", cid)
	}
	return pfx.Addr(), nil
}

func New(cfg *StaticOperatorConfig) (*Operator, error) {
	logger := log.New()
	logger.SetLevel(cfg.LogLevel)
	root := common.NewLogContext(context.Background(), logger)

	state := newOperatorState(root)

	// VNI registration + preset routes.
	cidrs := make(map[protocol.VNI_Ty]netip.Prefix)
	for vni, entry := range cfg.Network {
		prefix, err := netip.ParsePrefix(entry.CIDR)
		if err != nil {
			root.Cancel()
			return nil, fmt.Errorf("vni %s cidr %q: %w", vni, entry.CIDR, err)
		}
		cidrs[vni] = prefix
		state.registerVNI(vni, entry.Auth)
		if len(entry.PresetCIDmap) > 0 {
			vn, _ := state.vni(vni)
			for cid, pfx := range entry.PresetCIDmap {
				vn.routingMap.Set(cid, pfx)
			}
		}
		root.Log().Infof("VNet %s: %s (%d preset routes)", vni, prefix, len(entry.PresetCIDmap))
	}

	// One mapper closure shared by every listener.
	mapper := func(vni protocol.VNI_Ty) (handshake.VNIResolver, error) {
		state.mu.RLock()
		vn, ok := state.vnets[vni]
		cidr := cidrs[vni]
		state.mu.RUnlock()
		if !ok {
			return nil, fmt.Errorf("no config for vni %s", vni)
		}
		return &vniResolver{vn: vn, cidr: cidr}, nil
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

		conn, sc, err := ln.Accept()
		if err != nil {
			select {
			case <-o.lctx.Done():
				return
			default:
				logger.Errorf("Client accept failed (%s): %v", tp, err)
				continue
			}
		}
		if conn == nil || sc == nil {
			return
		}

		cp := newPeerClient(conn, sc)
		vn, err := o.state.addClient(cp)
		if err != nil {
			logger.Errorf("attach cid %s sessionindex %d to VNI %s: %v", cp.sc.CID, cp.sc.SessionIndex, cp.sc.VNI, err)
			_ = conn.Close()
			continue
		}

		logger.Infof("cid %s sessionindex %d connected on VNI %s from %s",
			cp.sc.CID, cp.sc.SessionIndex, cp.sc.VNI, conn.RemoteAddr())
		go o.routineReadFromClient(cp, vn)
	}
}

func (o *Operator) routineReadFromClient(cp *PeerClient, vn *vniEntry) {
	logger := o.lctx.Log()
	defer func() {
		o.state.removeClient(cp)
		_ = cp.Conn.Close()
		cp.closed.Store(true)
		logger.Infof("cid %s sessionindex %d disconnected", cp.sc.CID, cp.sc.SessionIndex)
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
			logger.Debugf("Read from cid %s sessionindex %d: %v", cp.sc.CID, cp.sc.SessionIndex, err)
			return
		}
		if n == 0 {
			continue
		}

		if err := vn.forwardFrame(readBuf[:n], cp); err != nil {
			logger.Debugf("Forward from cid %s sessionindex %d: %v", cp.sc.CID, cp.sc.SessionIndex, err)
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
				logger.Warnf("Reaping idle cid %s sessionindex %d", cp.sc.CID, cp.sc.SessionIndex)
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
