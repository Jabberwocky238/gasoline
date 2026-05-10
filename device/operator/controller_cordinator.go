package operator

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
	"golang.org/x/net/websocket"
)

// CordinatorController is the operator's outbound websocket client to
// a remote coordinator. Wire is line-delimited text:
//
//	operator -> cordinator
//	  hello  <uuid-hex> <udp-endpoint>
//	  attach <vni> <cid> <prefix>
//	  detach <vni> <cid>
//
//	cordinator -> operator
//	  peer online  <uuid-hex> <udp-endpoint>
//	  peer offline <uuid-hex>
//	  route set    <vni> <cid> <prefix> <uuid-hex>
//	  route del    <vni> <cid>
type CordinatorController struct {
	endpoint string
	state    *operatorState

	mu   sync.Mutex
	conn *websocket.Conn

	lctx        *common.LogContext
	wg          sync.WaitGroup
	unsubscribe func()
}

// NewCordinator returns an unstarted CordinatorController targeting endpoint.
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

// Start dials the coordinator, says hello, replays existing local
// clients, subscribes to future client events, and spins a read loop.
func (c *CordinatorController) Start() error {
	conn, err := websocket.Dial(c.endpoint, "", "http://localhost/")
	if err != nil {
		return fmt.Errorf("cordinator: dial %s: %w", c.endpoint, err)
	}
	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()
	c.lctx.Log().Infof("connected")

	// Announce ourselves so the coordinator can broadcast peer-online
	// to everyone else and stamp our UDP underlay endpoint.
	_ = c.send(fmt.Sprintf("hello %s %s",
		hex.EncodeToString(c.state.uuid[:]),
		c.state.Peers.Addr(),
	))

	// Replay any clients that already attached before we connected.
	c.state.mu.RLock()
	for vni, vn := range c.state.vnets {
		for _, cp := range vn.Clients() {
			pfx, ok := vn.routingMap.LookupByCID(cp.sc.CID)
			if !ok {
				continue
			}
			_ = c.send(fmt.Sprintf("attach %d %s %s",
				vni, protocol.FormatCID(cp.sc.CID), pfx.String()))
		}
	}
	c.state.mu.RUnlock()

	// Hook future events.
	c.unsubscribe = c.state.SubscribeClientEvents(c.onClientEvent)

	c.wg.Add(1)
	go c.readLoop()
	return nil
}

// Close cancels the context, closes the websocket, unsubscribes, and
// waits for the read loop to exit.
func (c *CordinatorController) Close() error {
	c.lctx.Cancel()
	if c.unsubscribe != nil {
		c.unsubscribe()
		c.unsubscribe = nil
	}
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

// onClientEvent is invoked on every local handshake / disconnect. It
// forwards the event to the coordinator so peers can update their
// routingMaps.
func (c *CordinatorController) onClientEvent(vni protocol.VNI_Ty, cid protocol.CID_Ty, prefix netip.Prefix, attached bool) {
	if attached {
		_ = c.send(fmt.Sprintf("attach %d %s %s", vni, protocol.FormatCID(cid), prefix.String()))
	} else {
		_ = c.send(fmt.Sprintf("detach %d %s", vni, protocol.FormatCID(cid)))
	}
}

func (c *CordinatorController) send(msg string) error {
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
		if err := c.handleInbound(line); err != nil {
			logger.Debugf("inbound %q: %v", line, err)
		}
	}
	if err := scanner.Err(); err != nil {
		select {
		case <-c.lctx.Done():
		default:
			logger.Errorf("read: %v", err)
		}
	}
}

// handleInbound parses one wire line from the coordinator and applies it.
func (c *CordinatorController) handleInbound(line string) error {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil
	}
	switch fields[0] {
	case "peer":
		if len(fields) < 3 {
			return fmt.Errorf("peer: need subcommand + uuid")
		}
		uuid, err := decodeUUID(fields[2])
		if err != nil {
			return fmt.Errorf("peer: %w", err)
		}
		switch fields[1] {
		case "online":
			if len(fields) != 4 {
				return fmt.Errorf("peer online: usage 'peer online <uuid> <udp-endpoint>'")
			}
			ap, err := netip.ParseAddrPort(fields[3])
			if err != nil {
				return fmt.Errorf("peer online: bad endpoint %q: %v", fields[3], err)
			}
			if uuid == c.state.uuid {
				return nil // ignore self
			}
			c.state.Peers.Add(NewPeerOperator(uuid, ap))
			return nil
		case "offline":
			c.state.Peers.Remove(uuid)
			return nil
		default:
			return fmt.Errorf("peer: unknown op %q", fields[1])
		}

	case "route":
		if len(fields) < 4 {
			return fmt.Errorf("route: too few fields")
		}
		vni, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			return fmt.Errorf("route: bad vni %q: %v", fields[2], err)
		}
		switch fields[1] {
		case "set":
			// route set <vni> <cid> <prefix> <uuid>
			if len(fields) != 6 {
				return fmt.Errorf("route set: usage 'route set <vni> <cid> <prefix> <uuid>'")
			}
			cid, err := protocol.ParseCID(fields[3])
			if err != nil {
				return err
			}
			pfx, err := netip.ParsePrefix(fields[4])
			if err != nil {
				return fmt.Errorf("route set: bad prefix: %w", err)
			}
			uuid, err := decodeUUID(fields[5])
			if err != nil {
				return err
			}
			vn, ok := c.state.vni(protocol.VNI_Ty(vni))
			if !ok {
				return fmt.Errorf("route set: unknown vni %d", vni)
			}
			if uuid == c.state.uuid {
				// Our own client; routingMap already has it (added at handshake).
				_ = cid
				return nil
			}
			vn.routingMap.SetOperator(uuid, pfx)
			_ = cid // cid identity is informational on operator routes; LPM uses prefix
			return nil

		case "del":
			// route del <vni> <cid>
			if len(fields) != 4 {
				return fmt.Errorf("route del: usage 'route del <vni> <cid>'")
			}
			cid, err := protocol.ParseCID(fields[3])
			if err != nil {
				return err
			}
			vn, ok := c.state.vni(protocol.VNI_Ty(vni))
			if !ok {
				return nil
			}
			vn.routingMap.DeleteByCID(cid)
			return nil
		default:
			return fmt.Errorf("route: unknown op %q", fields[1])
		}

	default:
		return fmt.Errorf("unknown command %q", fields[0])
	}
}

func decodeUUID(s string) ([16]byte, error) {
	var u [16]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return u, fmt.Errorf("bad uuid %q: %v", s, err)
	}
	if len(b) != 16 {
		return u, fmt.Errorf("uuid %q: want 16 bytes, got %d", s, len(b))
	}
	copy(u[:], b)
	return u, nil
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
