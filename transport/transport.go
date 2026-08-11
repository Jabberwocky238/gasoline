package transport

import (
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/handshake"
	"github.com/jabberwocky238/gasoline/protocol/noise"
)

// ClientIdentity is the Noise key material a client dials with: its own static
// key pair (its identity) plus the server's static public key (the "K" in
// Noise_IK — known in advance, like WireGuard's PublicKey= config).
type ClientIdentity struct {
	Priv      noise.PrivateKey
	Pub       noise.PublicKey
	ServerPub noise.PublicKey
}

// Conn is a packet-oriented connection.
// Each ReadPacket returns exactly one IP packet.
// Each WritePacket sends exactly one IP packet.
// Framing is handled internally per transport:
//   - UDP: one datagram = one packet (no framing needed)
//   - QUIC: length-prefix framing over the stream
//
// LastActive returns the timestamp of the most recent successful
// ReadPacket or WritePacket. Callers (operator, client) use this to
// determine session liveness without application-level keepalives.
type Conn interface {
	ReadPacket(buf []byte) (int, error)
	WritePacket(data []byte) error
	Close() error
	RemoteAddr() string
	LastActive() time.Time
}

// Accepted is what a Listener yields per inbound connection: the packet conn
// plus the AUTHENTICATION product (the client's identity key and the derived
// Noise session). IP/session assignment is NOT here — the caller runs the
// control plane (package control) over Conn using Session to produce a
// protocol.SessionContext.
type Accepted struct {
	Conn      Conn
	VNI       protocol.VNI_Ty
	ClientPub noise.PublicKey
	Session   *noise.Session
	// C2SKey/S2CKey are the raw data-plane keys to replicate into Raft so any
	// PE can decrypt this session's frames (PRD §7.2).
	C2SKey [32]byte
	S2CKey [32]byte
}

// Dialed is the client-side counterpart: the conn plus the authenticated
// session. The caller then runs the control-plane exchange to learn its IP.
type Dialed struct {
	Conn    Conn
	Session *noise.Session
}

// Dialer creates outbound connections and authenticates (handshake only).
type Dialer interface {
	Dial(endpoint string) (Dialed, error)
}

// Listener accepts inbound connections and authenticates (handshake only).
type Listener interface {
	Accept() (Accepted, error)
	Close() error
	Addr() string
}

// --------------- Factory + registry ---------------
//
// Each transport package self-registers a (DialerFactory, ListenerFactory)
// pair under a string name (e.g. "udp", "quic") in its
// init(). Callers go through transport.NewDialer / transport.NewListener
// so the operator and client don't have to import each transport
// concrete package directly.

// DialerFactory builds a Dialer for one outbound session. tlsConf may
// be nil for transports that don't need it (udp).
type DialerFactory func(cfg protocol.PresetSessionConfig, id ClientIdentity, tlsConf *tls.Config) (Dialer, error)

// ListenerFactory binds a Listener on addr. tlsConf may be nil for
// transports that don't need it.
type ListenerFactory func(addr string, mapper handshake.VNIMapperFn, tlsConf *tls.Config) (Listener, error)

type factoryEntry struct {
	dialer   DialerFactory
	listener ListenerFactory
}

var (
	registryMu sync.RWMutex
	registry   = map[string]factoryEntry{}
)

// Register installs the (dialer, listener) factories for transport
// name. Either factory may be nil if that side isn't supported. Calls
// after init are allowed but not goroutine-safe with concurrent
// NewDialer/NewListener.
func Register(name string, d DialerFactory, l ListenerFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[name] = factoryEntry{dialer: d, listener: l}
}

// Names returns every registered transport name in arbitrary order.
func Names() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	return out
}

// NewDialer dispatches to the registered DialerFactory for name.
func NewDialer(name string, cfg protocol.PresetSessionConfig, id ClientIdentity, tlsConf *tls.Config) (Dialer, error) {
	registryMu.RLock()
	e, ok := registry[name]
	registryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("transport: unknown %q", name)
	}
	if e.dialer == nil {
		return nil, fmt.Errorf("transport %q: no dialer registered", name)
	}
	return e.dialer(cfg, id, tlsConf)
}

// NewListener dispatches to the registered ListenerFactory for name.
func NewListener(name, addr string, mapper handshake.VNIMapperFn, tlsConf *tls.Config) (Listener, error) {
	registryMu.RLock()
	e, ok := registry[name]
	registryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("transport: unknown %q", name)
	}
	if e.listener == nil {
		return nil, fmt.Errorf("transport %q: no listener registered", name)
	}
	return e.listener(addr, mapper, tlsConf)
}
