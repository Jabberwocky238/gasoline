package ctrl

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Config for the control plane.
type Config struct {
	UUID         *[16]byte // optional, random if nil
	ListenAddr   string    // gRPC listen address
	ExternalAddr string    // address peers use to reach us
	DiscoverAddrs []string // seed addresses for bootstrap

	// Callbacks for side effects outside ctrl's domain.
	// Called synchronously from gRPC handlers — keep them fast.
	OnSessionSync   func(vnetID [16]byte, ip netip.Addr)
	OnSessionRevoke func(vnetID [16]byte, sessionID [16]byte, ip netip.Addr)
}

// ControlPlane manages inter-operator gRPC communication, peer connections,
// and cluster state (operator registry + remote session table).
type ControlPlane struct {
	ctx    context.Context
	cancel context.CancelFunc

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

	ctx, cancel := context.WithCancel(context.Background())
	return &ControlPlane{
		ctx:      ctx,
		cancel:   cancel,
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
		log.Infof("Control plane gRPC listening on %s", ln.Addr())
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
	c.Peers.Add(NewPeer(remoteUUID, resp.ExternalAddr, conn))
	c.Registry.SetOperator(remoteUUID, &OperatorInfo{Addr: resp.ExternalAddr})
	log.Infof("Registered with operator %x at %s", remoteUUID, resp.ExternalAddr)
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
	log.Infof("Dial-back to %x at %s", uuid, addr)
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
	log.Infof("Pong from %x: RTT=%v", uuid, rtt)
	return nil
}

// BroadcastSessionSync notifies all peers about a new client session.
func (c *ControlPlane) BroadcastSessionSync(sessionID, vnetID [16]byte, ip netip.Addr) {
	ip4 := ip.As4()
	event := &SessionEvent{
		Event: &SessionEvent_Sync{
			Sync: &SessionSync{
				SessionId:    sessionID[:],
				VnetId:       vnetID[:],
				OperatorUuid: c.uuid[:],
				IpAddr:       ip4[:],
				PrefixBits:   32,
			},
		},
	}
	for _, peer := range c.Peers.All() {
		if _, err := peer.Client.NotifySession(c.ctx, event); err != nil {
			log.Errorf("SessionSync to %x: %v", peer.UUID, err)
		}
	}
}

// BroadcastSessionRevoke notifies all peers that a client disconnected.
func (c *ControlPlane) BroadcastSessionRevoke(sessionID, vnetID [16]byte) {
	event := &SessionEvent{
		Event: &SessionEvent_Revoke{
			Revoke: &SessionRevoke{
				SessionId: sessionID[:],
				VnetId:    vnetID[:],
			},
		},
	}
	for _, peer := range c.Peers.All() {
		if _, err := peer.Client.NotifySession(c.ctx, event); err != nil {
			log.Errorf("SessionRevoke to %x: %v", peer.UUID, err)
		}
	}
}

// LookupRemoteSession finds which operator owns a destination IP in a given VNet.
func (c *ControlPlane) LookupRemoteSession(vnetID [16]byte, dstIP netip.Addr) (operatorUUID [16]byte, found bool) {
	vnet, ok := c.Registry.GetVNet(vnetID)
	if !ok {
		return [16]byte{}, false
	}
	return vnet.LookupByIP(dstIP)
}

// --------------- bootstrap / discover ---------------

func (c *ControlPlane) bootstrap() {
	for _, addr := range c.cfg.DiscoverAddrs {
		if addr == "" {
			continue
		}
		log.Infof("Bootstrapping from seed %s", addr)
		if err := c.DialOperator(addr); err != nil {
			log.Errorf("Bootstrap dial %s: %v", addr, err)
		}
	}
	for _, peer := range c.Peers.All() {
		resp, err := peer.Client.Discover(c.ctx, &DiscoverReq{})
		if err != nil {
			log.Errorf("Discover from %x: %v", peer.UUID, err)
			continue
		}
		c.processDiscoverResp(resp)
	}
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
		log.Infof("Discovered operator %x at %s, connecting...", uuid, e.Addr)
		go func(addr string) {
			if err := c.DialOperator(addr); err != nil {
				log.Errorf("Discover dial %s: %v", addr, err)
			}
		}(e.Addr)
	}
}
