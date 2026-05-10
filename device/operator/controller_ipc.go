package operator

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/jabberwocky238/gasoline/common"
)

// IPCController is a Unix-domain-socket controller: gasoctl (or any
// other local process) connects to it and writes one command per line.
// All operations land on the shared ControllerBase.
type IPCController struct {
	path     string
	listener net.Listener
	base     *ControllerBase

	lctx *common.LogContext
	wg   sync.WaitGroup
}

// NewIPC binds a Unix socket at path. The socket file is created with
// 0600 permissions and removed on Close. If a stale socket exists at
// path it is removed first.
func NewIPC(base *ControllerBase, path string) (*IPCController, error) {
	if base == nil || base.state == nil {
		return nil, fmt.Errorf("ipc: nil base")
	}
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

	return &IPCController{
		path:     path,
		listener: ln,
		base:     base,
		lctx:     base.state.lctx.WithField("component", "ipc"),
	}, nil
}

func (i *IPCController) Name() string { return "ipc" }
func (i *IPCController) Path() string { return i.path }

// Start begins accepting connections and dispatching commands.
func (i *IPCController) Start() error {
	i.wg.Add(1)
	go i.acceptLoop()
	return nil
}

// Close shuts the listener, removes the socket file, and waits for
// in-flight handlers to finish.
func (i *IPCController) Close() error {
	i.lctx.Cancel()
	err := i.listener.Close()
	_ = os.Remove(i.path)
	i.wg.Wait()
	return err
}

// dispatchLine routes one gasoctl command line through the shared
// ControllerBase. Each subsystem owns its own subcommand parsing
// (see dispatchRoute / dispatchCordinator) which today still consume
// the legacy line vocabulary directly on operatorState; replacing
// those with control.Op encode/decode is a follow-up.
func (i *IPCController) dispatchLine(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return errReply("empty command")
	}
	switch fields[0] {
	case "route":
		return i.base.state.dispatchRoute(fields[1:])
	case "cordinator":
		return i.base.state.dispatchCordinator(fields[1:])
	default:
		return errReply(fmt.Sprintf("unknown command %q", fields[0]))
	}
}

func (i *IPCController) acceptLoop() {
	defer i.wg.Done()
	logger := i.lctx.Log()
	for {
		conn, err := i.listener.Accept()
		if err != nil {
			select {
			case <-i.lctx.Done():
				return
			default:
				logger.Errorf("accept: %v", err)
				return
			}
		}
		i.wg.Add(1)
		go i.serveConn(conn)
	}
}

func (i *IPCController) serveConn(conn net.Conn) {
	defer i.wg.Done()
	defer conn.Close()
	logger := i.lctx.Log()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		select {
		case <-i.lctx.Done():
			return
		default:
		}
		reply := i.dispatchLine(scanner.Text())
		if _, err := conn.Write([]byte(reply + "\n")); err != nil {
			logger.Debugf("write reply: %v", err)
			return
		}
	}
	if err := scanner.Err(); err != nil {
		logger.Debugf("read: %v", err)
	}
}
