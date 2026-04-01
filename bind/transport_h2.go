package bind

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

const h2TunnelPath = "/.well-known/gasoline/h2"

type H2Client struct {
	TLSConfig *tls.Config
	Client    *http.Client
	Path      string
}

func (c *H2Client) Dial(ctx context.Context, address string) (TransportConn, error) {
	path := c.Path
	if path == "" {
		path = h2TunnelPath
	}

	client := c.Client
	if client == nil {
		tlsConfig := c.TLSConfig
		if tlsConfig == nil {
			tlsConfig = &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"h2"},
			}
		} else {
			tlsConfig = tlsConfig.Clone()
			if len(tlsConfig.NextProtos) == 0 {
				tlsConfig.NextProtos = []string{"h2"}
			}
		}

		client = &http.Client{
			Transport: &http2.Transport{
				TLSClientConfig: tlsConfig,
			},
		}
	}

	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+address+path, pr)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(req)
	if err != nil {
		_ = pr.CloseWithError(err)
		_ = pw.CloseWithError(err)
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = pr.Close()
		_ = pw.Close()
		_ = resp.Body.Close()
		return nil, errors.New("h2 tunnel rejected with status " + resp.Status)
	}

	return &h2Conn{
		reader:     resp.Body,
		writer:     pw,
		localAddr:  dummyAddr("h2-client"),
		remoteAddr: dummyAddr(address),
	}, nil
}

type H2Server struct {
	TLSConfig *tls.Config
	Server    *http.Server
	Path      string

	mu       sync.RWMutex
	listener net.Listener
	acceptCh chan *h2Conn
	closeCh  chan struct{}
}

func (s *H2Server) Listen(address string) error {
	path := s.Path
	if path == "" {
		path = h2TunnelPath
	}

	tlsConfig, err := s.serverTLSConfig()
	if err != nil {
		return err
	}
	if len(tlsConfig.NextProtos) == 0 {
		tlsConfig.NextProtos = []string{"h2"}
	}

	ln, err := tls.Listen("tcp", address, tlsConfig)
	if err != nil {
		return err
	}

	acceptCh := make(chan *h2Conn, 128)
	closeCh := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.ProtoMajor != 2 {
			http.Error(w, "h2 required", http.StatusHTTPVersionNotSupported)
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		conn := &h2Conn{
			reader:     r.Body,
			writer:     flushWriter{w: w, f: flusher},
			localAddr:  listenerAddr(ln),
			remoteAddr: parseRemoteAddr(r.RemoteAddr),
		}

		select {
		case acceptCh <- conn:
		case <-closeCh:
			_ = r.Body.Close()
			return
		case <-r.Context().Done():
			_ = r.Body.Close()
			return
		}

		<-r.Context().Done()
	})

	server := s.Server
	if server == nil {
		server = &http.Server{}
	} else {
		server = cloneHTTPServer(server)
	}
	server.Handler = mux

	if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
		_ = ln.Close()
		return err
	}

	s.mu.Lock()
	s.listener = ln
	s.acceptCh = acceptCh
	s.closeCh = closeCh
	s.Server = server
	s.mu.Unlock()

	go func() {
		_ = server.Serve(ln)
		close(acceptCh)
	}()

	return nil
}

func (s *H2Server) Accept(ctx context.Context) (TransportConn, error) {
	s.mu.RLock()
	acceptCh := s.acceptCh
	s.mu.RUnlock()

	if acceptCh == nil {
		return nil, errors.New("h2 listener is not started")
	}

	select {
	case conn, ok := <-acceptCh:
		if !ok {
			return nil, net.ErrClosed
		}
		return conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *H2Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closeCh != nil {
		select {
		case <-s.closeCh:
		default:
			close(s.closeCh)
		}
	}

	var firstErr error
	if s.Server != nil {
		if err := s.Server.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if s.listener != nil {
		if err := s.listener.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	s.listener = nil
	s.acceptCh = nil
	s.closeCh = nil
	return firstErr
}

func (s *H2Server) Addr() net.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

func (s *H2Server) serverTLSConfig() (*tls.Config, error) {
	if s.TLSConfig != nil {
		return s.TLSConfig.Clone(), nil
	}

	cert, err := generateSelfSignedCert()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}, nil
}

type h2Conn struct {
	reader     io.ReadCloser
	writer     io.WriteCloser
	localAddr  net.Addr
	remoteAddr net.Addr

	readMu  sync.Mutex
	writeMu sync.Mutex
	closeMu sync.Mutex
	closed  bool
}

func (c *h2Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	return c.reader.Read(p)
}

func (c *h2Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.writer.Write(p)
}

func (c *h2Conn) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	var firstErr error
	if err := c.reader.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := c.writer.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func (c *h2Conn) LocalAddr() net.Addr  { return c.localAddr }
func (c *h2Conn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *h2Conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *h2Conn) SetReadDeadline(time.Time) error  { return nil }
func (c *h2Conn) SetWriteDeadline(time.Time) error { return nil }

type flushWriter struct {
	w http.ResponseWriter
	f http.Flusher
}

func (w flushWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if err == nil {
		w.f.Flush()
	}
	return n, err
}

func (w flushWriter) Close() error {
	return nil
}

type dummyAddr string

func (a dummyAddr) Network() string { return "h2" }
func (a dummyAddr) String() string  { return string(a) }

func listenerAddr(ln net.Listener) net.Addr {
	if ln == nil {
		return dummyAddr("h2-server")
	}
	return ln.Addr()
}

func parseRemoteAddr(addr string) net.Addr {
	if host, port, err := net.SplitHostPort(addr); err == nil {
		return &net.TCPAddr{IP: net.ParseIP(host), Port: mustAtoi(port)}
	}
	return dummyAddr(strings.TrimSpace(addr))
}

func mustAtoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func cloneHTTPServer(src *http.Server) *http.Server {
	dst := *src
	return &dst
}
