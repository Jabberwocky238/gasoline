// Package quicksocks5 exposes a SOCKS5 server (driven by
// things-go/go-socks5) bound to a listener on the host. It's the
// "--quick-socks5" flag's implementation: any peer reachable on the
// overlay can hit this port and tunnel TCP/UDP through the local
// machine's physical network.
//
// Observability layered on top of the library's default silent
// behaviour. Every line is INFO, keyed by `peer` (the remote TCP
// addr), so multi-stage events correlate cleanly:
//
//	TCP connect       — peer=X:Y
//	handshake ok      — peer=X:Y method=no-auth
//	CONNECT/ASSOCIATE — peer=X:Y atyp=ipv4|ipv6|domain target=...
//
// ATYP gets a human-readable name so you can see at a glance whether
// the client is asking us to dial an IP (v4 or v6) or a domain that
// needs resolving, or requesting a UDP relay (usually with ATYP=ipv4
// and target=0.0.0.0:0 because the client announces itself as
// unspecified).
//
// Noisy library messages that duplicate our own structured events
// ("client want to used addr ...") are filtered out at logAdapter.
package quicksocks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"
	socks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

// Server wraps a running SOCKS5 listener + server. Call Close to tear
// down the listener; the goroutine exits when Accept returns an error.
type Server struct {
	listener net.Listener
	logger   *log.Entry
}

// Start binds a SOCKS5 server on 0.0.0.0:port and begins accepting
// connections in the background. Cancelling `parent`'s context doesn't
// stop Serve directly — callers must invoke Server.Close().
func Start(parent context.Context, port int, logger *log.Entry) (*Server, error) {
	if logger == nil {
		logger = log.NewEntry(log.StandardLogger())
	}
	logger = logger.WithField("component", "socks5")

	addr := fmt.Sprintf("0.0.0.0:%d", port)
	raw, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	wrapped := &loggingListener{Listener: raw, logger: logger}

	server := socks5.NewServer(
		socks5.WithLogger(logAdapter{logger}),
		socks5.WithAuthMethods([]socks5.Authenticator{&loggingNoAuth{logger: logger}}),
		socks5.WithConnectMiddleware(cmdLog(logger, "CONNECT")),
		socks5.WithAssociateMiddleware(cmdLog(logger, "ASSOCIATE")),
		socks5.WithBindMiddleware(cmdLog(logger, "BIND")),
	)

	s := &Server{listener: wrapped, logger: logger}
	go func() {
		logger.Infof("listening on %s", addr)
		if err := server.Serve(wrapped); err != nil {
			select {
			case <-parent.Done():
			default:
				logger.Errorf("server error: %v", err)
			}
		}
	}()
	return s, nil
}

// Close stops the listener. Any in-flight SOCKS5 sessions held by the
// server's goroutine pool will terminate when the peer closes.
func (s *Server) Close() error {
	if s == nil || s.listener == nil {
		return nil
	}
	return s.listener.Close()
}

// ---- logging helpers ----

// logAdapter forwards the library's Errorf into our logrus entry at
// INFO level. We additionally filter out messages that duplicate what
// our own listener / authenticator / middleware already logged.
type logAdapter struct {
	entry *log.Entry
}

func (a logAdapter) Errorf(format string, args ...interface{}) {
	// The library pre-announces the UDP listener on every UDP_ASSOCIATE
	// and duplicates our ASSOCIATE middleware log — drop it.
	if strings.HasPrefix(format, "client want to used addr") {
		return
	}
	a.entry.Infof(format, args...)
}

// loggingListener signals the very first moment a peer arrives: TCP
// accepted, no SOCKS5 bytes exchanged yet. Useful to diagnose probes
// that disconnect before sending a greeting.
type loggingListener struct {
	net.Listener
	logger *log.Entry
}

func (l *loggingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.logger.WithField("peer", c.RemoteAddr().String()).Info("TCP connect")
	return c, nil
}

// loggingNoAuth implements no-auth and emits one log line once the
// server has committed to MethodNoAuth and written the reply. After
// this point the next bytes will be a CMD request.
type loggingNoAuth struct {
	logger *log.Entry
}

func (a *loggingNoAuth) GetCode() uint8 { return statute.MethodNoAuth }

func (a *loggingNoAuth) Authenticate(_ io.Reader, writer io.Writer, userAddr string) (*socks5.AuthContext, error) {
	if _, err := writer.Write([]byte{statute.VersionSocks5, statute.MethodNoAuth}); err != nil {
		return nil, err
	}
	a.logger.WithFields(log.Fields{
		"peer":   userAddr,
		"method": "no-auth",
	}).Info("handshake ok")
	return &socks5.AuthContext{
		Method:  statute.MethodNoAuth,
		Payload: map[string]string{},
	}, nil
}

// cmdLog returns a pre-handler middleware that logs a single line per
// request with structured fields. `kind` is CONNECT / ASSOCIATE / BIND.
// `atyp` shows whether the target is IPv4, IPv6, or a domain awaiting
// resolution — a key hint when debugging why a flow fails (e.g. domain
// targets require the server's OS resolver to work).
func cmdLog(entry *log.Entry, kind string) socks5.Middleware {
	return func(_ context.Context, _ io.Writer, request *socks5.Request) error {
		peer := ""
		if request.RemoteAddr != nil {
			peer = request.RemoteAddr.String()
		}
		target := ""
		if request.DestAddr != nil {
			if request.DestAddr.FQDN != "" {
				target = fmt.Sprintf("%s:%d", request.DestAddr.FQDN, request.DestAddr.Port)
			} else {
				target = fmt.Sprintf("%s:%d", request.DestAddr.IP, request.DestAddr.Port)
			}
		}
		entry.WithFields(log.Fields{
			"peer":   peer,
			"atyp":   atypName(request.DestAddr),
			"target": target,
		}).Info(kind)
		return nil
	}
}

// atypName maps the SOCKS5 ATYP byte to a readable tag. ipv4/ipv6/domain
// are what appears in the log; "?" covers malformed or future values.
func atypName(a *statute.AddrSpec) string {
	if a == nil {
		return "?"
	}
	switch a.AddrType {
	case statute.ATYPIPv4:
		return "ipv4"
	case statute.ATYPIPv6:
		return "ipv6"
	case statute.ATYPDomain:
		return "domain"
	default:
		return fmt.Sprintf("atyp-%d", a.AddrType)
	}
}
