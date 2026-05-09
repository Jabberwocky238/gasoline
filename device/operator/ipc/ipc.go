package ipc

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"sync"

	log "github.com/sirupsen/logrus"
)

// Handler is invoked once per line received on the IPC socket.
// Returning an error closes the offending connection.
type Handler func(ctx context.Context, msg []byte) error

// IPC is a Unix-domain-socket listener that hands every received line
// to Handler. Default behavior is a no-op handler.
type IPC struct {
	path     string
	listener net.Listener
	handler  Handler

	ctx    context.Context
	cancel context.CancelFunc
	log    *log.Logger

	wg sync.WaitGroup
}

// NewIPC binds a Unix socket at path. The socket file is created with
// 0600 permissions and removed on Close. If a stale socket exists at
// path it is removed first.
func NewIPC(path string) (*IPC, error) {
	if path == "" {
		return nil, fmt.Errorf("ipc: empty socket path")
	}
	if _, err := os.Stat(path); err == nil {
		_ = os.Remove(path)
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("ipc: listen %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("ipc: chmod %s: %w", path, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &IPC{
		path:     path,
		listener: ln,
		handler:  func(context.Context, []byte) error { return nil },
		ctx:      ctx,
		cancel:   cancel,
		log:      log.New(),
	}, nil
}

// SetHandler installs the message handler. Safe to call before Start.
func (i *IPC) SetHandler(h Handler) {
	if h == nil {
		h = func(context.Context, []byte) error { return nil }
	}
	i.handler = h
}

// Path returns the bound socket path.
func (i *IPC) Path() string { return i.path }

// Start begins accepting connections and dispatching messages.
func (i *IPC) Start() {
	i.wg.Add(1)
	go i.acceptLoop()
}

// Close shuts the listener, removes the socket file, and waits for
// in-flight handlers to finish.
func (i *IPC) Close() error {
	i.cancel()
	err := i.listener.Close()
	_ = os.Remove(i.path)
	i.wg.Wait()
	return err
}

func (i *IPC) acceptLoop() {
	defer i.wg.Done()
	for {
		conn, err := i.listener.Accept()
		if err != nil {
			select {
			case <-i.ctx.Done():
				return
			default:
				i.log.Errorf("ipc: accept: %v", err)
				return
			}
		}
		i.wg.Add(1)
		go i.serveConn(conn)
	}
}

func (i *IPC) serveConn(conn net.Conn) {
	defer i.wg.Done()
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		select {
		case <-i.ctx.Done():
			return
		default:
		}
		if err := i.handler(i.ctx, scanner.Bytes()); err != nil {
			i.log.Debugf("ipc: handler: %v", err)
			return
		}
	}
	if err := scanner.Err(); err != nil {
		i.log.Debugf("ipc: read: %v", err)
	}
}
