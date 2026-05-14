package operator

import (
	"bufio"
	"fmt"
	"net/netip"
	"sync"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/control"
	"golang.org/x/net/websocket"
)

// CordinatorController is the operator's outbound websocket client to
// a remote coordinator. Wire is JSON envelopes (one per line) — see
// protocol/control: every frame is `{"kind":<u8>,"body":{...}}`.
//
// Outbound (operator -> cordinator):
//
//	PeerJoin{UUID:self, Endpoint:underlay-UDP}    — on Start
//	RouteUpsert{VNI, CID, Prefix, OwnerUUID:self} — on client attach
//	RouteRemove{VNI, CID}                          — on client detach
//
// Inbound (cordinator -> operator), dispatched to ControllerBase.Consume:
//
//	PeerJoin / PeerLeave    — update PeerTable
//	RouteUpsert / RouteRemove — update vniEntry.routingMap
//	CordinatorConnectReply  — replay snapshot of peers
type CordinatorController struct {
	endpoint string
	base     *ControllerBase

	mu   sync.Mutex
	conn *websocket.Conn

	lctx        *common.LogContext
	wg          sync.WaitGroup
	unsubscribe func()
}

// NewCordinator returns an unstarted CordinatorController targeting endpoint.
func NewCordinator(base *ControllerBase, endpoint string) (*CordinatorController, error) {
	if base == nil || base.state == nil {
		return nil, fmt.Errorf("cordinator: nil base")
	}
	if endpoint == "" {
		return nil, fmt.Errorf("cordinator: empty endpoint")
	}
	return &CordinatorController{
		endpoint: endpoint,
		base:     base,
		lctx:     base.state.lctx.WithField("component", "cordinator").WithField("endpoint", endpoint),
	}, nil
}

func (c *CordinatorController) Name() string     { return "cordinator" }
func (c *CordinatorController) Endpoint() string { return c.endpoint }

// Start dials the coordinator, announces self via PeerJoin, replays
// existing local clients as RouteUpsert events, subscribes to future
// client events, and spins a read loop.
func (c *CordinatorController) Start() error {
	conn, err := websocket.Dial(c.endpoint, "", "http://localhost/")
	if err != nil {
		return fmt.Errorf("cordinator: dial %s: %w", c.endpoint, err)
	}
	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()
	c.lctx.Log().Infof("connected")

	// Announce ourselves so the coordinator can broadcast PeerJoin to
	// every other operator and stamp our UDP underlay endpoint.
	endpoint, err := parseUnderlayAddr(c.base.state.Peers.Addr())
	if err == nil {
		_ = c.sendOp(&control.PeerJoin{UUID: c.base.state.uuid, Endpoint: endpoint})
	}

	// Replay any clients that already attached before we connected.
	c.base.state.mu.RLock()
	for vni, vn := range c.base.state.vnets {
		for _, cp := range vn.Clients() {
			pfx, ok := vn.routingMap.LookupByCID(cp.sc.CID)
			if !ok {
				continue
			}
			_ = c.sendOp(&control.RouteUpsert{
				VNI:       vni,
				CID:       cp.sc.CID,
				Prefix:    pfx,
				OwnerUUID: c.base.state.uuid,
			})
		}
	}
	c.base.state.mu.RUnlock()

	// Hook future events.
	c.unsubscribe = c.base.state.SubscribeClientEvents(c.onClientEvent)

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
// routingMaps. OwnerUUID is always self — this operator owns the
// client side of any route announced from here.
func (c *CordinatorController) onClientEvent(vni protocol.VNI_Ty, cid protocol.CID_Ty, prefix netip.Prefix, attached bool) {
	if attached {
		_ = c.sendOp(&control.RouteUpsert{
			VNI:       vni,
			CID:       cid,
			Prefix:    prefix,
			OwnerUUID: c.base.state.uuid,
		})
	} else {
		_ = c.sendOp(&control.RouteRemove{VNI: vni, CID: cid})
	}
}

func (c *CordinatorController) sendOp(op control.Op) error {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("cordinator: not connected")
	}
	body, err := control.MarshalJSON(op)
	if err != nil {
		return fmt.Errorf("cordinator: marshal %T: %w", op, err)
	}
	body = append(body, '\n')
	if _, err := conn.Write(body); err != nil {
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
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		op, err := control.UnmarshalJSON(line)
		if err != nil {
			logger.Debugf("inbound: %v (line=%q)", err, string(line))
			continue
		}
		// Reply ops, if any, are sent back through the same socket.
		if reply := c.base.Consume(op); reply != nil {
			_ = c.sendOp(reply)
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

// parseUnderlayAddr converts a "host:port" string from PeerTable.Addr()
// into the AddrPort form PeerJoin carries.
func parseUnderlayAddr(s string) (netip.AddrPort, error) {
	if s == "" {
		return netip.AddrPort{}, fmt.Errorf("cordinator: underlay not bound")
	}
	return netip.ParseAddrPort(s)
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
		if err := s.cordinatorDisconnect(); err != nil {
			return errReply(err.Error())
		}
		return "OK"

	default:
		return errReply(fmt.Sprintf("cordinator: unknown op %q", args[0]))
	}
}
