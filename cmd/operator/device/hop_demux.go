package operator

import (
	"net/netip"
	"sync"
	"time"

	"github.com/jabberwocky238/gasoline/cmd/operator/device/consensus"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/dataframe"
	"github.com/jabberwocky238/gasoline/protocol/noise"
	"github.com/jabberwocky238/gasoline/transport"
)

// hoppedConn is a transport.Conn for a session that hopped in from another PE:
// it never handshook here, so there is no real connection — writes seal under
// the session's S2CKey and go to the session's current source address over the
// listener's shared socket (PRD §6.4). Reads are unsupported: inbound frames
// arrive through the listener demux, not this conn.
type hoppedConn struct {
	ln   transport.HoppableListener
	sess *noise.Session
	tag  dataframe.SessionTag

	mu   sync.Mutex
	dst  netip.AddrPort
	last time.Time
}

func (c *hoppedConn) WritePacket(pkt []byte) error {
	frame, err := dataframe.Seal(c.sess, c.tag, pkt)
	if err != nil {
		return err
	}
	c.mu.Lock()
	dst := c.dst
	c.last = time.Now()
	c.mu.Unlock()
	return c.ln.WriteTo(dst, frame)
}

// ReadPacket is never called: the demux feeds inbound frames directly. It
// blocks-then-errors only if wired by mistake.
func (c *hoppedConn) ReadPacket([]byte) (int, error) {
	return 0, errHoppedNoRead
}
func (c *hoppedConn) Close() error        { return nil }
func (c *hoppedConn) RemoteAddr() string  { c.mu.Lock(); defer c.mu.Unlock(); return c.dst.String() }
func (c *hoppedConn) LastActive() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

var errHoppedNoRead = errHopped("hoppedConn: ReadPacket not supported")

type errHopped string

func (e errHopped) Error() string { return string(e) }

// setDst updates the source address a hopped session is currently reachable at.
func (c *hoppedConn) setDst(dst netip.AddrPort) {
	c.mu.Lock()
	c.dst = dst
	c.last = time.Now()
	c.mu.Unlock()
}

// hopTable tracks sessions currently hopped in on this PE (i.e. served here but
// not handshook here). Keyed by full SessionID. The reconstructed noise.Session
// carries the per-PE replay window (PRD §7.5 — the window is local, not
// replicated), so it must be cached, not rebuilt per packet.
type hopTable struct {
	mu    sync.Mutex
	byTag map[dataframe.SessionTag]*hoppedEntry
}

type hoppedEntry struct {
	keys      consensus.SessionKeys
	cp        *PeerClient
	conn      *hoppedConn
	installed bool // routing + local client installed for this PE
}

func newHopTable() *hopTable {
	return &hopTable{byTag: make(map[dataframe.SessionTag]*hoppedEntry)}
}

// installHopDemux wires the operator's data demux into a hoppable listener, so a
// data frame arriving from an unknown source for an existing session is served
// here instead of triggering a fresh handshake (PRD §6.4 / §5.4.3).
func (o *Operator) installHopDemux(ln transport.Listener) {
	hl, ok := ln.(transport.HoppableListener)
	if !ok {
		return // transport can't hop (e.g. QUIC); nothing to install
	}
	hl.SetDataDemux(func(src netip.AddrPort, datagram []byte) bool {
		return o.demuxHopped(hl, src, datagram)
	})
}

// demuxHopped is the DataDemux: it claims a datagram as a data frame for an
// already-established session. Returns false (decline → handshake) when the
// datagram is not a recognizable frame for a known session.
func (o *Operator) demuxHopped(hl transport.HoppableListener, src netip.AddrPort, datagram []byte) bool {
	node := o.state.node
	if node == nil {
		return false // no consensus: no cross-PE session state to hop to
	}
	tag, counter, ct, err := dataframe.ParseHeader(datagram)
	if err != nil {
		return false
	}
	keys, ok := node.SessionByTag(tag)
	if !ok {
		return false // unknown tag → treat as a new handshake
	}

	entry := o.hops.getOrCreate(hl, tag, keys, o.state.nextSessionIndex)
	entry.conn.setDst(src)

	// Decrypt with the session's C2SKey (client->PE). A tag collision or forged
	// frame fails here → decline so it can (harmlessly) fall through.
	pt, err := dataframe.Open(entry.conn.sess, counter, ct, true)
	if err != nil {
		return false
	}

	vn, ok := o.state.vni(keys.VNI)
	if !ok {
		return true // consumed but undeliverable
	}

	// First time we serve this hopped session, take ownership: install the
	// local route so return traffic reaches this hopped conn, add it to the VNI
	// client set, and commit a SessionMigrate so the whole mesh routes srcIP
	// here (PRD §5.4.3). Guarded so it runs once, not per packet.
	if o.hops.markInstalled(tag) {
		vn.addClient(entry.cp)
		vn.routingMap.SetClient(keys.SessionID, netip.PrefixFrom(keys.IP, keys.IP.BitLen()))
		o.migrateSession(keys.SessionID)
	}

	// Route the plaintext IP packet (dst-IP based), re-sealing per destination.
	if err := vn.forwardFrame(pt, entry.cp); err != nil {
		o.lctx.Log().Debugf("hop forward sid %s: %v", keys.SessionID, err)
	}
	return true
}

// getOrCreate returns the hop entry for tag, building the reconstructed session
// (seal=S2CKey, open=C2SKey) and its hopped conn on first sight. nextIndex mints
// the local session index for the hopped client (avoids colliding on index 0).
func (t *hopTable) getOrCreate(hl transport.HoppableListener, tag dataframe.SessionTag, keys consensus.SessionKeys, nextIndex func() uint32) *hoppedEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.byTag[tag]; ok {
		return e
	}
	sess, err := noise.SessionFromKeys(keys.S2CKey, keys.C2SKey)
	if err != nil {
		// Should not happen (keys are valid 32-byte); return a stub that will
		// fail Open and cause the caller to decline.
		sess, _ = noise.SessionFromKeys([32]byte{}, [32]byte{})
	}
	conn := &hoppedConn{ln: hl, sess: sess, tag: tag}
	sc := &protocol.SessionContext{
		SessionID:    keys.SessionID,
		VNI:          keys.VNI,
		SessionIndex: nextIndex(),
		IP:           keys.IP,
	}
	cp := newPeerClient(conn, sc, sess)
	e := &hoppedEntry{keys: keys, cp: cp, conn: conn}
	t.byTag[tag] = e
	return e
}

// markInstalled reports whether this call is the first to claim ownership of
// tag's session on this PE (returns true once, false thereafter).
func (t *hopTable) markInstalled(tag dataframe.SessionTag) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.byTag[tag]
	if !ok || e.installed {
		return false
	}
	e.installed = true
	return true
}

// migrateSession batches a SessionMigrate proposal recording this PE as the
// session's current access point (PRD §6.3 — access-point change is batched,
// not per-packet).
func (o *Operator) migrateSession(sid protocol.SessionID_Ty) {
	if o.state.node == nil {
		return
	}
	go func() {
		err := o.state.node.MigrateSession(&consensus.SessionMigrate{
			SessionID: sid,
			Operator:  o.uuid,
			Now:       time.Now().UnixNano(),
		}, 5*time.Second)
		if err != nil {
			o.lctx.Log().Debugf("migrate sid %s: %v", sid, err)
		}
	}()
}
