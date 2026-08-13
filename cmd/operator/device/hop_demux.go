package operator

import (
	"net/netip"
	"sync"
	"time"

	"github.com/jabberwocky238/gasoline/cmd/operator/device/consensus"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/datacom"
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
	tag  datacom.SessionTag

	mu   sync.Mutex
	dst  netip.AddrPort
	last time.Time
}

func (c *hoppedConn) WritePacket(pkt []byte) error {
	frame, err := datacom.Seal(c.sess, c.tag, pkt)
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
func (c *hoppedConn) Close() error       { return nil }
func (c *hoppedConn) RemoteAddr() string { c.mu.Lock(); defer c.mu.Unlock(); return c.dst.String() }
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
	byTag map[datacom.SessionTag]*hoppedEntry
}

type hoppedEntry struct {
	keys      consensus.SessionKeys
	cp        *PeerClient
	sess      *noise.Session  // reconstructed data-plane session (owns replay window)
	conn      *hoppedConn     // set for UDP hops (shared-socket reply path)
	qconn     *quicHoppedConn // set for QUIC hops (per-connection reply path)
	installed bool            // routing + local client installed for this PE
}

// quicHoppedConn is a transport.Conn for a QUIC-hopped session: writes seal
// under S2CKey and go back through the current stream's sendFrame closure (PRD
// §5.4.4). The closure is swapped whenever the client re-hops onto a new
// connection.
type quicHoppedConn struct {
	sess *noise.Session
	tag  datacom.SessionTag

	mu     sync.Mutex
	send   func([]byte) error
	last   time.Time
	remote string
}

func (c *quicHoppedConn) WritePacket(pkt []byte) error {
	frame, err := datacom.Seal(c.sess, c.tag, pkt)
	if err != nil {
		return err
	}
	c.mu.Lock()
	send := c.send
	c.last = time.Now()
	c.mu.Unlock()
	if send == nil {
		return errHoppedNoRead
	}
	return send(frame)
}

func (c *quicHoppedConn) ReadPacket([]byte) (int, error) { return 0, errHoppedNoRead }
func (c *quicHoppedConn) Close() error                   { return nil }
func (c *quicHoppedConn) RemoteAddr() string             { c.mu.Lock(); defer c.mu.Unlock(); return c.remote }
func (c *quicHoppedConn) LastActive() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.last }

func (c *quicHoppedConn) setSender(send func([]byte) error) {
	c.mu.Lock()
	c.send = send
	c.last = time.Now()
	c.mu.Unlock()
}

func newHopTable() *hopTable {
	return &hopTable{byTag: make(map[datacom.SessionTag]*hoppedEntry)}
}

// installHopDemux wires the operator's data demux into a hoppable listener, so a
// data frame arriving from an unknown source for an existing session is served
// here instead of triggering a fresh handshake (PRD §6.4 / §5.4.3). Handles both
// the UDP (shared-socket) and QUIC (per-connection) hop shapes.
func (o *Operator) installHopDemux(ln transport.Listener) {
	switch hl := ln.(type) {
	case transport.HoppableListener:
		hl.SetDataDemux(func(src netip.AddrPort, datagram []byte) bool {
			return o.demuxHopped(hl, src, datagram)
		})
	case transport.QUICHoppableListener:
		hl.SetDataDemux(func(remote string, firstFrame []byte, sendFrame func([]byte) error) bool {
			return o.demuxHoppedQUIC(firstFrame, sendFrame)
		})
	}
}

// demuxHoppedQUIC serves a data frame that arrived on a freshly-dialed QUIC
// connection (PRD §5.4.4). Replies go back through sendFrame (the same stream).
// Returns true iff the frame belonged to a known session.
func (o *Operator) demuxHoppedQUIC(datagram []byte, sendFrame func([]byte) error) bool {
	node := o.state.node
	if node == nil {
		return false
	}
	tag, counter, ct, err := datacom.ParseHeader(datagram)
	if err != nil {
		return false
	}
	keys, ok := node.SessionByTag(tag)
	if !ok {
		return false
	}

	entry := o.hops.getOrCreateQUIC(tag, keys, o.state.nextSessionIndex, o.operatorTag(), sendFrame)
	// Keep the reply path fresh: a later hop to a new connection updates it.
	entry.qconn.setSender(sendFrame)

	pt, err := datacom.Open(entry.sess, counter, ct, true)
	if err != nil {
		return false
	}

	vn, ok := o.state.vni(keys.VNI)
	if !ok {
		return true
	}
	if o.hops.markInstalled(tag) {
		vn.addClient(entry.cp)
		vn.routingMap.SetClient(keys.SessionID, netip.PrefixFrom(keys.IP, keys.IP.BitLen()))
		o.migrateSession(keys.SessionID)
	}
	if err := vn.forwardFrame(pt, entry.cp); err != nil {
		o.lctx.Log().Debugf("quic hop forward sid %s: %v", keys.SessionID, err)
	}
	return true
}

// demuxHopped is the DataDemux: it claims a datagram as a data frame for an
// already-established session. Returns false (decline → handshake) when the
// datagram is not a recognizable frame for a known session.
func (o *Operator) demuxHopped(hl transport.HoppableListener, src netip.AddrPort, datagram []byte) bool {
	node := o.state.node
	if node == nil {
		return false // no consensus: no cross-PE session state to hop to
	}
	tag, counter, ct, err := datacom.ParseHeader(datagram)
	if err != nil {
		return false
	}
	keys, ok := node.SessionByTag(tag)
	if !ok {
		return false // unknown tag → treat as a new handshake
	}

	entry := o.hops.getOrCreate(hl, tag, keys, o.state.nextSessionIndex, o.operatorTag())
	entry.conn.setDst(src)

	// Decrypt with the session's C2SKey (client->PE). A tag collision or forged
	// frame fails here → decline so it can (harmlessly) fall through.
	pt, err := datacom.Open(entry.sess, counter, ct, true)
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
func (t *hopTable) getOrCreate(hl transport.HoppableListener, tag datacom.SessionTag, keys consensus.SessionKeys, nextIndex func() uint32, opTag uint16) *hoppedEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.byTag[tag]; ok {
		return e
	}
	sess, err := noise.SessionFromKeys(keys.S2CKey, keys.C2SKey, opTag)
	if err != nil {
		// Should not happen (keys are valid 32-byte); return a stub that will
		// fail Open and cause the caller to decline.
		sess, _ = noise.SessionFromKeys([32]byte{}, [32]byte{}, opTag)
	}
	conn := &hoppedConn{ln: hl, sess: sess, tag: tag}
	sc := &protocol.SessionContext{
		SessionID:    keys.SessionID,
		VNI:          keys.VNI,
		SessionIndex: nextIndex(),
		IP:           keys.IP,
	}
	cp := newPeerClient(conn, sc, sess)
	e := &hoppedEntry{keys: keys, cp: cp, sess: sess, conn: conn}
	t.byTag[tag] = e
	return e
}

// getOrCreateQUIC is the QUIC analogue of getOrCreate: the reply path is a
// per-connection sendFrame closure rather than a shared socket.
func (t *hopTable) getOrCreateQUIC(tag datacom.SessionTag, keys consensus.SessionKeys, nextIndex func() uint32, opTag uint16, send func([]byte) error) *hoppedEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.byTag[tag]; ok {
		return e
	}
	sess, err := noise.SessionFromKeys(keys.S2CKey, keys.C2SKey, opTag)
	if err != nil {
		sess, _ = noise.SessionFromKeys([32]byte{}, [32]byte{}, opTag)
	}
	qconn := &quicHoppedConn{sess: sess, tag: tag, send: send, last: time.Now()}
	sc := &protocol.SessionContext{
		SessionID:    keys.SessionID,
		VNI:          keys.VNI,
		SessionIndex: nextIndex(),
		IP:           keys.IP,
	}
	cp := newPeerClient(qconn, sc, sess)
	e := &hoppedEntry{keys: keys, cp: cp, sess: sess, qconn: qconn}
	t.byTag[tag] = e
	return e
}

// markInstalled reports whether this call is the first to claim ownership of
// tag's session on this PE (returns true once, false thereafter).
func (t *hopTable) markInstalled(tag datacom.SessionTag) bool {
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
