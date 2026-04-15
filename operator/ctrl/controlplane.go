package ctrl

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/jabberwocky238/gasoline/common"
)

// vniToBytes / vniFromBytes serialize the 24-bit VNI as a 4-byte big-endian
// slice on the wire (legacy proto field is `bytes vnet_id`).
func vniToBytes(vni common.VNI) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(vni))
	return b[:]
}

func vniFromBytes(b []byte) common.VNI {
	if len(b) != 4 {
		return 0
	}
	return common.VNI(binary.BigEndian.Uint32(b))
}

// Config for the control plane.
type Config struct {
	UUID         *[16]byte // optional, random if nil
	ListenAddr   string    // gRPC listen address
	ExternalAddr string    // address peers use to reach us
	DiscoverAddrs []string // seed addresses for bootstrap
	Log          *log.Logger // optional, defaults to logrus standard logger

	// Callbacks for side effects outside ctrl's domain.
	// Called synchronously from gRPC handlers — keep them fast.
	OnSessionSync   func(vni common.VNI, opUUID [16]byte, vmac common.VMAC, ip netip.Addr)
	OnSessionRevoke func(vni common.VNI, opUUID [16]byte, sessionID [16]byte, vmac common.VMAC, ip netip.Addr)
}

// ControlPlane manages inter-operator gRPC communication, peer connections,
// and cluster state (operator registry + remote session table).
type ControlPlane struct {
	ctx    context.Context
	cancel context.CancelFunc
	log    *log.Logger

	cfg *Config

	uuid     [16]byte
	Peers    *PeerTable
	Registry *Registry

	grpcServer   *grpc.Server
	grpcListener net.Listener
}

func New(cfg *Config) *ControlPlane {
	var uuid [16]byte
	if cfg.UUID != nil {
		uuid = *cfg.UUID
	} else {
		rand.Read(uuid[:])
	}

	logger := cfg.Log
	if logger == nil {
		logger = log.StandardLogger()
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &ControlPlane{
		ctx:      ctx,
		cancel:   cancel,
		log:      logger,
		cfg:      cfg,
		uuid:     uuid,
		Peers:    NewPeerTable(),
		Registry: NewRegistry(),
	}
}

func (c *ControlPlane) UUID() [16]byte       { return c.uuid }
func (c *ControlPlane) ExternalAddr() string { return c.cfg.ExternalAddr }
func (c *ControlPlane) SetExternalAddr(addr string) { c.cfg.ExternalAddr = addr }

func (c *ControlPlane) GRPCAddr() string {
	if c.grpcListener != nil {
		return c.grpcListener.Addr().String()
	}
	return ""
}

// Start launches the gRPC server and bootstraps discovery.
func (c *ControlPlane) Start() error {
	if len(c.cfg.DiscoverAddrs) > 0 && c.cfg.ExternalAddr == "" {
		return fmt.Errorf("discover requires an external address")
	}

	if c.cfg.ListenAddr != "" {
		ln, err := net.Listen("tcp", c.cfg.ListenAddr)
		if err != nil {
			return fmt.Errorf("ctrl listen on %s: %w", c.cfg.ListenAddr, err)
		}
		c.grpcListener = ln
		c.grpcServer = grpc.NewServer()
		RegisterOperatorServiceServer(c.grpcServer, &server{cp: c})
		c.log.Infof("Control plane gRPC listening on %s", ln.Addr())
		go c.grpcServer.Serve(ln)
	}

	if len(c.cfg.DiscoverAddrs) > 0 {
		go c.bootstrap()
	}

	return nil
}

func (c *ControlPlane) Stop() {
	c.cancel()
	if c.grpcServer != nil {
		c.grpcServer.GracefulStop()
	}
	c.Peers.CloseAll()
}

// DialOperator connects to a remote operator, registers, and adds as peer.
// Silently skips when the remote turns out to be ourselves (a headless DNS
// expansion will include our own IP).
func (c *ControlPlane) DialOperator(addr string) error {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	client := NewOperatorServiceClient(conn)
	resp, err := client.Register(c.ctx, &RegisterReq{
		Uuid:         c.uuid[:],
		ExternalAddr: c.cfg.ExternalAddr,
	})
	if err != nil {
		conn.Close()
		return fmt.Errorf("register with %s: %w", addr, err)
	}

	var remoteUUID [16]byte
	copy(remoteUUID[:], resp.Uuid)
	if remoteUUID == c.uuid {
		conn.Close()
		return nil
	}
	if _, ok := c.Peers.Get(remoteUUID); ok {
		conn.Close()
		return nil
	}
	c.Peers.Add(NewPeer(remoteUUID, resp.ExternalAddr, conn))
	c.Registry.SetOperator(remoteUUID, &OperatorInfo{Addr: resp.ExternalAddr})
	c.log.Infof("Registered with operator %x at %s", remoteUUID, resp.ExternalAddr)
	return nil
}

// dialBack creates a gRPC client to a remote operator without Register RPC.
func (c *ControlPlane) dialBack(addr string, uuid [16]byte) error {
	if _, ok := c.Peers.Get(uuid); ok {
		return nil
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	c.Peers.Add(NewPeer(uuid, addr, conn))
	c.log.Infof("Dial-back to %x at %s", uuid, addr)
	return nil
}

// PingOperator sends a Ping RPC and records RTT.
func (c *ControlPlane) PingOperator(uuid [16]byte) error {
	peer, ok := c.Peers.Get(uuid)
	if !ok {
		return fmt.Errorf("operator %x not found", uuid)
	}
	sent := time.Now()
	resp, err := peer.Client.Ping(c.ctx, &PingReq{UnixNano: sent.UnixNano()})
	if err != nil {
		return err
	}
	rtt := time.Duration(time.Now().UnixNano() - resp.UnixNano)
	if info, ok := c.Registry.GetOperator(uuid); ok {
		info.PingCost = rtt
		info.LastPing = time.Now()
		c.Registry.SetOperator(uuid, info)
	}
	c.log.Infof("Pong from %x: RTT=%v", uuid, rtt)
	return nil
}

// BroadcastSessionSync notifies all peers about a new client session.
func (c *ControlPlane) BroadcastSessionSync(sessionID [16]byte, vni common.VNI, cid common.VMAC, ip netip.Addr) {
	var ipBytes []byte
	if ip.Is4() {
		a4 := ip.As4()
		ipBytes = a4[:]
	} else {
		a16 := ip.As16()
		ipBytes = a16[:]
	}
	event := &SessionEvent{
		Event: &SessionEvent_Sync{
			Sync: &SessionSync{
				SessionId:    sessionID[:],
				Vni:          vniToBytes(vni),
				OperatorUuid: c.uuid[:],
				IpAddr:       ipBytes,
				PrefixBits:   uint32(ip.BitLen()),
				Cid:          append([]byte(nil), cid[:]...),
			},
		},
	}
	for _, peer := range c.Peers.All() {
		if _, err := peer.Client.NotifySession(c.ctx, event); err != nil {
			c.log.Errorf("SessionSync to %x: %v", peer.UUID, err)
		}
	}
}

// BroadcastSessionRevoke notifies all peers that a client disconnected.
func (c *ControlPlane) BroadcastSessionRevoke(sessionID [16]byte, vni common.VNI) {
	event := &SessionEvent{
		Event: &SessionEvent_Revoke{
			Revoke: &SessionRevoke{
				SessionId: sessionID[:],
				Vni:       vniToBytes(vni),
			},
		},
	}
	for _, peer := range c.Peers.All() {
		if _, err := peer.Client.NotifySession(c.ctx, event); err != nil {
			c.log.Errorf("SessionRevoke to %x: %v", peer.UUID, err)
		}
	}
}

// LookupRemoteByVMAC finds which operator owns a given (VNI, ClientID).
// Primary forwarding lookup on the data plane — no IP parsing involved.
func (c *ControlPlane) LookupRemoteByVMAC(vni common.VNI, cid common.VMAC) (sessionID, operatorUUID [16]byte, found bool) {
	vnet, ok := c.Registry.GetVNet(vni)
	if !ok {
		return [16]byte{}, [16]byte{}, false
	}
	sid, info, ok := vnet.LookupByVMAC(cid)
	if !ok {
		return [16]byte{}, [16]byte{}, false
	}
	return sid, info.OperatorUUID, true
}

// --------------- bootstrap / discover ---------------

func (c *ControlPlane) bootstrap() {
	for _, addr := range c.cfg.DiscoverAddrs {
		if addr == "" {
			continue
		}
		for _, expanded := range expandHost(c.ctx, addr, c.log) {
			c.log.Infof("Bootstrapping from seed %s", expanded)
			if err := c.DialOperator(expanded); err != nil {
				c.log.Errorf("Bootstrap dial %s: %v", expanded, err)
			}
		}
	}
	for _, peer := range c.Peers.All() {
		resp, err := peer.Client.Discover(c.ctx, &DiscoverReq{})
		if err != nil {
			c.log.Errorf("Discover from %x: %v", peer.UUID, err)
			continue
		}
		c.processDiscoverResp(resp)
	}
}

// expandHost resolves the host portion of "host:port" via the system DNS
// resolver and returns one "ip:port" entry per A/AAAA record. Required
// for Kubernetes headless Services where the DNS name maps to N peer pod
// IPs and we want one Peer entry per IP — gRPC's pick_first balancer
// would otherwise stick to a single backend.
//
// Falls back to [addr] verbatim when:
//   - the host is already an IP literal (LookupHost returns just it);
//   - SplitHostPort fails (callers handed us bare junk — let the dialer
//     surface the error);
//   - the lookup fails (transient DNS hiccup; let dial fail loudly).
func expandHost(ctx context.Context, addr string, logger *log.Logger) []string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return []string{addr}
	}
	if ip := net.ParseIP(host); ip != nil {
		return []string{addr}
	}
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil || len(ips) == 0 {
		if logger != nil {
			logger.Warnf("dns lookup %s: %v", host, err)
		}
		return []string{addr}
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, net.JoinHostPort(ip, port))
	}
	return out
}

func (c *ControlPlane) processDiscoverResp(resp *DiscoverResp) {
	for _, e := range resp.Operators {
		var uuid [16]byte
		copy(uuid[:], e.Uuid)
		if uuid == c.uuid {
			continue
		}
		if _, ok := c.Peers.Get(uuid); ok {
			continue
		}
		c.log.Infof("Discovered operator %x at %s, connecting...", uuid, e.Addr)
		go func(addr string) {
			if err := c.DialOperator(addr); err != nil {
				c.log.Errorf("Discover dial %s: %v", addr, err)
			}
		}(e.Addr)
	}
}
