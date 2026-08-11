package client

import (
	"math/rand"
	"net/netip"
	"time"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/transport"
)

// defaultHopInterval is how often the client picks a fresh random hop target.
// Hopping is random (PRD §5.1), so this is just the churn rate, not a synced
// clock — the operator accepts frames on any advertised (server, port).
const defaultHopInterval = 3 * time.Second

// Hopper periodically repoints a HoppingConn at a random (server, port) drawn
// from the assignment's hop-target list (PRD §5/§6). It is a no-op when the
// conn cannot hop (e.g. QUIC) or the server list is empty.
type Hopper struct {
	conn     transport.HoppingConn
	servers  []protocol.HopServer
	interval time.Duration
	lctx     *common.LogContext
}

// NewHopper returns a Hopper, or nil if hopping is not possible (conn is not a
// HoppingConn, or no hop targets were advertised).
func NewHopper(parent *common.LogContext, conn transport.Conn, servers []protocol.HopServer) *Hopper {
	hc, ok := conn.(transport.HoppingConn)
	if !ok || len(servers) == 0 {
		return nil
	}
	return &Hopper{
		conn:     hc,
		servers:  servers,
		interval: defaultHopInterval,
		lctx:     parent.WithField("component", "hopper"),
	}
}

// Start launches the hop ticker.
func (h *Hopper) Start() { go h.loop() }

// Stop halts the ticker.
func (h *Hopper) Stop() { h.lctx.Cancel() }

func (h *Hopper) loop() {
	t := time.NewTicker(h.interval)
	defer t.Stop()
	for {
		select {
		case <-h.lctx.Done():
			return
		case <-t.C:
		}
		dst, ok := h.pick()
		if !ok {
			continue
		}
		if err := h.conn.SetHopDest(dst); err != nil {
			h.lctx.Log().Debugf("hop to %s: %v", dst, err)
			continue
		}
		h.lctx.Log().Debugf("hopped to %s", dst)
	}
}

// pick chooses a random (server, port-in-range) as a "host:port" string. ok is
// false if the list has no usable target.
func (h *Hopper) pick() (string, bool) {
	if len(h.servers) == 0 {
		return "", false
	}
	s := h.servers[rand.Intn(len(h.servers))]
	if !s.Host.IsValid() || len(s.Ports) == 0 {
		return "", false
	}
	r := s.Ports[rand.Intn(len(s.Ports))]
	lo, hi := r.Lo, r.Hi
	if hi < lo {
		lo, hi = hi, lo
	}
	port := lo
	if hi > lo {
		port = lo + uint16(rand.Intn(int(hi-lo)+1))
	}
	return netip.AddrPortFrom(s.Host, port).String(), true
}
