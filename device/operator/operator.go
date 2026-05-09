package operator

import (
	"context"
	"crypto/rand"
	"fmt"

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
type Operator struct {
	ctx    context.Context
	cancel context.CancelFunc
	cfg    *StaticOperatorConfig

	log  *log.Logger
	uuid [16]byte

	dataListenAddr  string
	clientListeners map[string]transport.Listener
	authResolver    *staticAuthResolver
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
	}, nil
}

// --------------- Identity / accessors ---------------

func (o *Operator) UUID() [16]byte { return o.uuid }

// ClientAddr returns the first client listener's bound address, or
// the empty string if no listener was configured.
func (o *Operator) ClientAddr() string {
	for _, ln := range o.clientListeners {
		return ln.Addr()
	}
	return ""
}

// --------------- Lifecycle ---------------

func (o *Operator) Start() error {
	for tp, ln := range o.clientListeners {
		o.log.Infof("Client endpoint (%s) listening on %s", tp, ln.Addr())
	}
	return nil
}

func (o *Operator) Close() error {
	o.cancel()
	closeAll(o.clientListeners)
	return nil
}

func closeAll(lns map[string]transport.Listener) {
	for _, ln := range lns {
		_ = ln.Close()
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
