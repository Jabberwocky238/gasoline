package consensus

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	"github.com/jabberwocky238/gasoline/protocol"
	transportQuic "github.com/jabberwocky238/gasoline/transport/quic"
)

// Peer names one member of the Raft cluster: a stable ID plus the QUIC
// address its stream layer listens on.
type Peer struct {
	ID   string // stable across restarts (operator UUID hex)
	Addr string // host:port of its Raft QUIC listener
}

// Config configures a consensus Node.
type Config struct {
	// LocalID is this node's stable Raft ID (operator UUID hex).
	LocalID string
	// BindAddr is the QUIC address this node's Raft transport listens on.
	BindAddr string
	// Peers is the initial cluster membership, used only when Bootstrap is
	// true (on exactly one node of a fresh cluster).
	Peers []Peer
	// Bootstrap seeds a brand-new cluster from Peers. Set on one node only.
	Bootstrap bool

	// ServerTLS / ClientTLS drive the QUIC transport. If nil, a self-signed
	// server config and an insecure client config are generated (fine for a
	// closed operator mesh; identity is the mesh's own concern, not TLS PKI).
	ServerTLS *tls.Config
	ClientTLS *tls.Config

	// Election timing. Zero values fall back to library defaults; tests set
	// these low for fast, deterministic elections.
	HeartbeatTimeout   time.Duration
	ElectionTimeout    time.Duration
	LeaderLeaseTimeout time.Duration
	CommitTimeout      time.Duration

	// LogOutput, if set, receives raft's internal logs. Tests pass io.Discard
	// (or a filtered writer) to keep output readable; production leaves it nil
	// so raft logs to stderr via its default hclog logger.
	LogOutput io.Writer
}

// Node wraps a raft.Raft plus its FSM and transport, exposing the operator's
// view of the mesh state and a Propose path for mutations.
type Node struct {
	raft  *raft.Raft
	fsm   *meshState
	layer *quicStreamLayer
	id    string
}

// NewNode constructs and starts a consensus node. It binds the QUIC transport,
// creates in-memory Raft stores, and (if Bootstrap) seeds the cluster.
func NewNode(cfg Config) (*Node, error) {
	if cfg.LocalID == "" {
		return nil, fmt.Errorf("consensus: LocalID required")
	}
	if cfg.BindAddr == "" {
		return nil, fmt.Errorf("consensus: BindAddr required")
	}

	serverTLS, clientTLS, err := resolveTLS(cfg.ServerTLS, cfg.ClientTLS)
	if err != nil {
		return nil, err
	}

	layer, err := newQUICStreamLayer(cfg.BindAddr, serverTLS, clientTLS)
	if err != nil {
		return nil, err
	}

	var logger hclog.Logger
	if cfg.LogOutput != nil {
		logger = hclog.New(&hclog.LoggerOptions{
			Name:   "raft-" + cfg.LocalID,
			Output: cfg.LogOutput,
			Level:  hclog.Warn,
		})
	}

	trans := raft.NewNetworkTransportWithConfig(&raft.NetworkTransportConfig{
		Stream:  layer,
		MaxPool: 3,
		Timeout: 10 * time.Second,
		Logger:  logger,
	})

	rc := raft.DefaultConfig()
	rc.LocalID = raft.ServerID(cfg.LocalID)
	applyTiming(rc, cfg)
	if logger != nil {
		rc.Logger = logger
	}

	fsm := NewMeshState()
	logStore := raft.NewInmemStore()
	stableStore := raft.NewInmemStore()
	snapStore := raft.NewInmemSnapshotStore()

	r, err := raft.NewRaft(rc, fsm, logStore, stableStore, snapStore, trans)
	if err != nil {
		_ = layer.Close()
		return nil, fmt.Errorf("consensus: new raft: %w", err)
	}

	if cfg.Bootstrap {
		servers := make([]raft.Server, 0, len(cfg.Peers))
		for _, p := range cfg.Peers {
			servers = append(servers, raft.Server{
				Suffrage: raft.Voter,
				ID:       raft.ServerID(p.ID),
				Address:  raft.ServerAddress(p.Addr),
			})
		}
		if f := r.BootstrapCluster(raft.Configuration{Servers: servers}); f.Error() != nil {
			// ErrCantBootstrap means the cluster already has state; tolerate it
			// so a restart of the bootstrap node is not fatal.
			if f.Error() != raft.ErrCantBootstrap {
				_ = layer.Close()
				return nil, fmt.Errorf("consensus: bootstrap: %w", f.Error())
			}
		}
	}

	return &Node{raft: r, fsm: fsm, layer: layer, id: cfg.LocalID}, nil
}

// applyTiming copies non-zero timing overrides onto the raft config.
func applyTiming(rc *raft.Config, cfg Config) {
	if cfg.HeartbeatTimeout > 0 {
		rc.HeartbeatTimeout = cfg.HeartbeatTimeout
	}
	if cfg.ElectionTimeout > 0 {
		rc.ElectionTimeout = cfg.ElectionTimeout
	}
	if cfg.LeaderLeaseTimeout > 0 {
		rc.LeaderLeaseTimeout = cfg.LeaderLeaseTimeout
	}
	if cfg.CommitTimeout > 0 {
		rc.CommitTimeout = cfg.CommitTimeout
	}
}

// resolveTLS fills in default TLS configs when the caller supplies none.
func resolveTLS(server, client *tls.Config) (*tls.Config, *tls.Config, error) {
	if server == nil {
		var err error
		server, err = transportQuic.GenerateServerTLS()
		if err != nil {
			return nil, nil, err
		}
	}
	if client == nil {
		client = transportQuic.InsecureClientTLS()
	}
	return server, client, nil
}

// --------------- mutation / query API ---------------

// Propose applies a command through Raft. On a follower it is forwarded to the
// leader by the caller (this returns ErrNotLeader). Blocks until the command
// commits or times out. The FSM's per-command error (e.g. IP collision) is
// surfaced via the ApplyResult.
func (n *Node) Propose(cmd *Command, timeout time.Duration) error {
	data, err := cmd.Encode()
	if err != nil {
		return err
	}
	f := n.raft.Apply(data, timeout)
	if err := f.Error(); err != nil {
		return err
	}
	if res, ok := f.Response().(ApplyResult); ok {
		return res.Err
	}
	return nil
}

// State exposes the local FSM replica for reads (no consensus round-trip).
func (n *Node) State() *meshState { return n.fsm }

// IsLeader reports whether this node currently holds leadership.
func (n *Node) IsLeader() bool { return n.raft.State() == raft.Leader }

// PickIP resolves a free address for pubkey on vni against the local replica
// (no consensus). See meshState.PickIP.
func (n *Node) PickIP(vni protocol.VNI_Ty, pubkey [32]byte) (netip.Addr, netip.Prefix, bool) {
	return n.fsm.PickIP(vni, pubkey)
}

// CommitSession proposes a SessionCreate through Raft (the durable commit of an
// IP + SessionID allocation). Returns consensus.ErrIPTaken if the IP was taken
// by a concurrent commit — the caller retries with a fresh pick.
func (n *Node) CommitSession(c *SessionCreate, timeout time.Duration) error {
	return n.Propose(&Command{Kind: CmdSessionCreate, SessionCreate: c}, timeout)
}

// LeaderID returns the current leader's Raft ID ("" if unknown).
func (n *Node) LeaderID() string {
	_, id := n.raft.LeaderWithID()
	return string(id)
}

// LeaderAddr returns the current leader's transport address ("" if unknown).
func (n *Node) LeaderAddr() string {
	addr, _ := n.raft.LeaderWithID()
	return string(addr)
}

// AddVoter adds a new voting member. Only valid on the leader.
func (n *Node) AddVoter(p Peer, timeout time.Duration) error {
	f := n.raft.AddVoter(raft.ServerID(p.ID), raft.ServerAddress(p.Addr), 0, timeout)
	return f.Error()
}

// Barrier blocks until all preceding logs are applied on this node — used by
// tests and readers that need read-your-writes after becoming leader.
func (n *Node) Barrier(timeout time.Duration) error {
	return n.raft.Barrier(timeout).Error()
}

// Shutdown stops Raft and closes the transport.
func (n *Node) Shutdown() error {
	err := n.raft.Shutdown().Error()
	_ = n.layer.Close()
	return err
}

// ID returns this node's Raft ID.
func (n *Node) ID() string { return n.id }
