package operator

import (
	"bufio"
	"fmt"
	"sync"

	"github.com/jabberwocky238/gasoline/common"
	"golang.org/x/net/websocket"
)

// CordinatorController is the operator's outbound websocket client to a
// remote coordinator. The wire format is line-delimited text on top of
// the websocket frames; semantics are TBD and currently logged only.
type CordinatorController struct {
	endpoint string
	state    *operatorState

	mu   sync.Mutex
	conn *websocket.Conn

	lctx *common.LogContext
	wg   sync.WaitGroup
}

// NewCordinator returns an unstarted CordinatorController targeting endpoint.
// endpoint is the full websocket URL (e.g. "ws://host:port/path").
func NewCordinator(state *operatorState, endpoint string) (*CordinatorController, error) {
	if state == nil {
		return nil, fmt.Errorf("cordinator: nil state")
	}
	if endpoint == "" {
		return nil, fmt.Errorf("cordinator: empty endpoint")
	}
	return &CordinatorController{
		endpoint: endpoint,
		state:    state,
		lctx:     state.lctx.WithField("component", "cordinator").WithField("endpoint", endpoint),
	}, nil
}

func (c *CordinatorController) Name() string     { return "cordinator" }
func (c *CordinatorController) Endpoint() string { return c.endpoint }

// Start dials the coordinator over websocket and spins a read loop.
func (c *CordinatorController) Start() error {
	conn, err := websocket.Dial(c.endpoint, "", "http://localhost/")
	if err != nil {
		return fmt.Errorf("cordinator: dial %s: %w", c.endpoint, err)
	}

	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()

	c.lctx.Log().Infof("connected")
	c.wg.Add(1)
	go c.readLoop()
	return nil
}

// Close cancels the context, closes the websocket, and waits for
// the read loop to exit.
func (c *CordinatorController) Close() error {
	c.lctx.Cancel()
	c.mu.Lock()
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	c.wg.Wait()
	return nil
}

// Send writes one line-delimited message to the coordinator. Returns
// an error if the connection is not open.
func (c *CordinatorController) Send(msg string) error {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("cordinator: not connected")
	}
	if _, err := conn.Write([]byte(msg + "\n")); err != nil {
		return fmt.Errorf("cordinator: write: %w", err)
	}
	return nil
}

func (c *CordinatorController) readLoop() {
	defer c.wg.Done()
	logger := c.lctx.Log()

	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		select {
		case <-c.lctx.Done():
			return
		default:
		}
		line := scanner.Text()
		// Wire semantics TBD. For now: log and drop. When the protocol
		// is decided this should dispatch into c.state similarly to
		// the IPC controller.
		logger.Debugf("<- %s", line)
	}
	if err := scanner.Err(); err != nil {
		select {
		case <-c.lctx.Done():
		default:
			logger.Errorf("read: %v", err)
		}
	}
}

// dispatchCordinator parses the args of a `cordinator ...` gasoctl
// command and applies it to s. Returns the gasoctl reply line.
func (s *operatorState) dispatchCordinator(args []string) string {
	if len(args) == 0 {
		return errReply("cordinator: missing subcommand")
	}
	switch args[0] {
	case "connect":
		if len(args) != 2 {
			return errReply("cordinator connect: usage 'cordinator connect <endpoint>'")
		}
		if err := s.cordinatorConnect(args[1]); err != nil {
			return errReply(err.Error())
		}
		return "OK"

	case "disconnect":
		if len(args) != 2 {
			return errReply("cordinator disconnect: usage 'cordinator disconnect <endpoint>'")
		}
		if err := s.cordinatorDisconnect(args[1]); err != nil {
			return errReply(err.Error())
		}
		return "OK"

	default:
		return errReply(fmt.Sprintf("cordinator: unknown op %q", args[0]))
	}
}
