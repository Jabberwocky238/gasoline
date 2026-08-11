package message

// DataCtrl is the in-band operator <-> client control channel. It
// shares the same transport.Conn as the IP data plane, multiplexed
// by piggybacking on "IP version = 3" frames (a reserved/invalid
// version that the data plane already drops everywhere).
//
// Wire layout (every datactrl frame):
//
//	byte 0  : 0x30        — IP-version=3, IHL=0 marker
//	byte 1  : Kind        — DataCtrl op discriminator
//	byte 2..: body        — kind-specific bytes (may be empty)
//
// Memory model — mirrors message-transport.go: every op carries a
// pool-rented backing buffer (common.WaitPool). Seal writes the full
// wire frame (prefix + kind + body) directly into that buffer with no
// intermediate copies; Open re-binds the op's view fields over an
// already-filled buffer (the receive path). Frame() exposes the wire
// bytes for transport.Conn.WritePacket — there is no second slice.
// Release returns the buffer to the pool; double-release is safe.
//
//	// send
//	op := message.NewPing()
//	_ = op.Seal()
//	_ = conn.WritePacket(op.Frame())
//	op.Release()
//
//	// receive (buffer already holds the wire frame)
//	op, err := message.ParseDataCtrl(buf)   // adopts buf
//	defer op.Release()

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
)

// DataCtrlPrefix is byte 0 on every datactrl frame: IP version 3.
const DataCtrlPrefix byte = 0x30

// dcHeaderSize is the prefix(1)+kind(1) shared header on every frame.
const dcHeaderSize = 2

// DataCtrlKind is the 1-byte discriminator at byte 1.
type DataCtrlKind uint8

const (
	DataCtrlPing          DataCtrlKind = 0x00 // client -> operator liveness probe
	DataCtrlPong          DataCtrlKind = 0x01 // operator -> client probe reply
	DataCtrlPrefixChanged DataCtrlKind = 0x02 // operator -> client: your assigned prefix moved
	DataCtrlPeerAdvertise DataCtrlKind = 0x03 // operator -> client: peer client joined/left this VNI
	DataCtrlRoutePush     DataCtrlKind = 0x04 // operator -> client: extra reachable prefixes
	DataCtrlRouteAck      DataCtrlKind = 0x05 // client  -> operator: confirms last push
	DataCtrlShutdown      DataCtrlKind = 0x06 // operator -> client: graceful tear-down
	DataCtrlStats         DataCtrlKind = 0x07 // client  -> operator: periodic counters
)

// DataCtrlOp is the union over all datactrl ops in this file. Frame
// returns the wire bytes (a view into the op's pooled Buffer); Release
// returns that buffer to the pool.
type DataCtrlOp interface {
	Kind() DataCtrlKind
	Frame() []byte
	Release()
}

// IsDataCtrl reports whether frame looks like an in-band control packet
// (IP version field = 3). Callers should run this before treating a
// received packet as IP data.
func IsDataCtrl(frame []byte) bool {
	return len(frame) >= 1 && frame[0]>>4 == 3
}

// ParseDataCtrl adopts an already-filled pool buffer and returns a
// typed op that views into it. On error the buffer is returned to the
// pool and (nil, err) is returned. On success the caller owns op and
// must call op.Release() to free the buffer.
func ParseDataCtrl(buf *[]byte) (DataCtrlOp, error) {
	if buf == nil {
		return nil, fmt.Errorf("datactrl: nil buffer")
	}
	b := *buf
	if len(b) < dcHeaderSize {
		common.PutBuffer(buf)
		return nil, fmt.Errorf("datactrl: short frame %d", len(b))
	}
	if b[0]>>4 != 3 {
		common.PutBuffer(buf)
		return nil, fmt.Errorf("datactrl: not v3 (got version %d)", b[0]>>4)
	}
	kind := DataCtrlKind(b[1])

	var op DataCtrlOp
	switch kind {
	case DataCtrlPing:
		op = &Ping{Buffer: buf}
	case DataCtrlPong:
		op = &Pong{Buffer: buf}
	case DataCtrlPrefixChanged:
		op = &PrefixChanged{Buffer: buf}
	case DataCtrlPeerAdvertise:
		op = &PeerAdvertise{Buffer: buf}
	case DataCtrlRoutePush:
		op = &RoutePush{Buffer: buf}
	case DataCtrlRouteAck:
		op = &RouteAck{Buffer: buf}
	case DataCtrlShutdown:
		op = &Shutdown{Buffer: buf}
	case DataCtrlStats:
		op = &Stats{Buffer: buf}
	default:
		common.PutBuffer(buf)
		return nil, fmt.Errorf("datactrl: unknown kind %#x", byte(kind))
	}
	if err := opOpen(op); err != nil {
		op.Release()
		return nil, fmt.Errorf("datactrl: open kind %#x: %w", byte(kind), err)
	}
	return op, nil
}

// opOpen is a non-interface dispatch so DataCtrlOp can stay narrow.
func opOpen(op DataCtrlOp) error {
	type opener interface{ Open() error }
	if o, ok := op.(opener); ok {
		return o.Open()
	}
	return nil
}

// ---------- shared buffer helpers ----------

// rentIfNil ensures *bufp points at a pool-rented buffer.
func rentIfNil(bufp **[]byte) {
	if *bufp == nil {
		*bufp = common.GetBuffer()
	}
}

// writeHeader writes prefix + kind at offset 0 and sets buffer length.
// Returns the buffer slice ready for body writes from offset 2.
func writeHeader(buf *[]byte, kind DataCtrlKind, bodySize int) ([]byte, error) {
	need := dcHeaderSize + bodySize
	if cap(*buf) < need {
		return nil, fmt.Errorf("datactrl: buffer too small (cap %d < need %d)", cap(*buf), need)
	}
	*buf = (*buf)[:need]
	b := *buf
	b[0] = DataCtrlPrefix
	b[1] = byte(kind)
	return b, nil
}

// release returns the buffer to the pool. Safe to call repeatedly.
func release(bufp **[]byte) {
	if *bufp != nil {
		**bufp = (**bufp)[:cap(**bufp)]
		common.PutBuffer(*bufp)
		*bufp = nil
	}
}

// --------------- Ping / Pong ---------------

// Ping is a client -> operator liveness probe. Body is empty.
type Ping struct{ Buffer *[]byte }

func NewPing() *Ping             { return &Ping{Buffer: common.GetBuffer()} }
func (*Ping) Kind() DataCtrlKind { return DataCtrlPing }
func (m *Ping) Frame() []byte    { return *m.Buffer }
func (m *Ping) Release()         { release(&m.Buffer) }
func (m *Ping) Seal() error {
	rentIfNil(&m.Buffer)
	_, err := writeHeader(m.Buffer, DataCtrlPing, 0)
	return err
}
func (*Ping) Open() error { return nil }

// Pong is the operator's reply to a Ping. Body is empty.
type Pong struct{ Buffer *[]byte }

func NewPong() *Pong             { return &Pong{Buffer: common.GetBuffer()} }
func (*Pong) Kind() DataCtrlKind { return DataCtrlPong }
func (m *Pong) Frame() []byte    { return *m.Buffer }
func (m *Pong) Release()         { release(&m.Buffer) }
func (m *Pong) Seal() error {
	rentIfNil(&m.Buffer)
	_, err := writeHeader(m.Buffer, DataCtrlPong, 0)
	return err
}
func (*Pong) Open() error { return nil }

// --------------- PrefixChanged ---------------

// PrefixChanged tells the client its assigned prefix has moved. The
// client should reconfigure its TUN address.
//
// Body wire layout: addrLen(1) + addr(0/4/16) + cidrBits(1).
type PrefixChanged struct {
	Buffer *[]byte

	// body view; rebound by Seal / Open.
	addr []byte // slice into Buffer (no copy)
	bits *byte  // pointer into Buffer
}

func NewPrefixChanged() *PrefixChanged { return &PrefixChanged{Buffer: common.GetBuffer()} }
func (*PrefixChanged) Kind() DataCtrlKind { return DataCtrlPrefixChanged }
func (m *PrefixChanged) Frame() []byte    { return *m.Buffer }
func (m *PrefixChanged) Release()         { release(&m.Buffer); m.addr = nil; m.bits = nil }

func (m *PrefixChanged) Seal(p netip.Prefix) error {
	rentIfNil(&m.Buffer)
	addr := p.Addr().AsSlice()
	b, err := writeHeader(m.Buffer, DataCtrlPrefixChanged, 1+len(addr)+1)
	if err != nil {
		return err
	}
	b[2] = byte(len(addr))
	copy(b[3:3+len(addr)], addr)
	b[3+len(addr)] = byte(p.Bits())
	m.bindViews()
	return nil
}

func (m *PrefixChanged) Open() error {
	b := *m.Buffer
	if len(b) < dcHeaderSize+1 {
		return fmt.Errorf("prefix-changed: short")
	}
	n := int(b[dcHeaderSize])
	if len(b) < dcHeaderSize+1+n+1 {
		return fmt.Errorf("prefix-changed: short (need %d, got %d)", dcHeaderSize+1+n+1, len(b))
	}
	m.bindViews()
	return nil
}

func (m *PrefixChanged) bindViews() {
	b := *m.Buffer
	n := int(b[dcHeaderSize])
	m.addr = b[dcHeaderSize+1 : dcHeaderSize+1+n]
	m.bits = &b[dcHeaderSize+1+n]
}

// Prefix decodes the addr/bits views into a netip.Prefix.
func (m *PrefixChanged) Prefix() netip.Prefix {
	addr, _ := netip.AddrFromSlice(m.addr)
	return netip.PrefixFrom(addr, int(*m.bits))
}

// --------------- PeerAdvertise ---------------

// PeerAdvertiseKind discriminates join vs leave for PeerAdvertise.
type PeerAdvertiseKind uint8

const (
	PeerAdvertiseJoin  PeerAdvertiseKind = 0
	PeerAdvertiseLeave PeerAdvertiseKind = 1
)

// PeerAdvertise lets a client know a sibling on its VNI just joined
// or left. Body: subKind(1) + SessionID(16) + addrLen(1) + addr + cidrBits(1).
type PeerAdvertise struct {
	Buffer *[]byte

	SubKind   *PeerAdvertiseKind     // pointer view into Buffer
	SessionID *protocol.SessionID_Ty // [16]byte view into Buffer
	addr      []byte                 // slice view into Buffer
	bits      *byte                  // pointer view into Buffer
}

func NewPeerAdvertise() *PeerAdvertise    { return &PeerAdvertise{Buffer: common.GetBuffer()} }
func (*PeerAdvertise) Kind() DataCtrlKind { return DataCtrlPeerAdvertise }
func (m *PeerAdvertise) Frame() []byte    { return *m.Buffer }
func (m *PeerAdvertise) Release() {
	release(&m.Buffer)
	m.SubKind = nil
	m.SessionID = nil
	m.addr = nil
	m.bits = nil
}

func (m *PeerAdvertise) Seal(sub PeerAdvertiseKind, sid protocol.SessionID_Ty, p netip.Prefix) error {
	rentIfNil(&m.Buffer)
	addr := p.Addr().AsSlice()
	b, err := writeHeader(m.Buffer, DataCtrlPeerAdvertise, 1+16+1+len(addr)+1)
	if err != nil {
		return err
	}
	b[2] = byte(sub)
	copy(b[3:19], sid[:])
	b[19] = byte(len(addr))
	copy(b[20:20+len(addr)], addr)
	b[20+len(addr)] = byte(p.Bits())
	m.bindViews()
	return nil
}

func (m *PeerAdvertise) Open() error {
	b := *m.Buffer
	if len(b) < dcHeaderSize+1+16+1 {
		return fmt.Errorf("peer-advertise: short")
	}
	n := int(b[dcHeaderSize+1+16])
	if len(b) < dcHeaderSize+1+16+1+n+1 {
		return fmt.Errorf("peer-advertise: short (need %d, got %d)", dcHeaderSize+1+16+1+n+1, len(b))
	}
	m.bindViews()
	return nil
}

func (m *PeerAdvertise) bindViews() {
	b := *m.Buffer
	m.SubKind = (*PeerAdvertiseKind)(&b[dcHeaderSize])
	m.SessionID = (*protocol.SessionID_Ty)(b[dcHeaderSize+1 : dcHeaderSize+1+16])
	n := int(b[dcHeaderSize+1+16])
	m.addr = b[dcHeaderSize+1+16+1 : dcHeaderSize+1+16+1+n]
	m.bits = &b[dcHeaderSize+1+16+1+n]
}

// Prefix decodes the addr/bits views into a netip.Prefix.
func (m *PeerAdvertise) Prefix() netip.Prefix {
	addr, _ := netip.AddrFromSlice(m.addr)
	return netip.PrefixFrom(addr, int(*m.bits))
}

// --------------- RoutePush / RouteAck ---------------

// RoutePush carries a batch of extra prefixes the client should
// consider reachable through this operator.
//
// Body wire layout: count(2) + N × (addrLen(1) + addr + cidrBits(1)).
// Variable-shape entries don't admit fixed pointer views, so iteration
// reads directly from the Buffer slice with no per-entry allocation.
type RoutePush struct {
	Buffer *[]byte
}

func NewRoutePush() *RoutePush         { return &RoutePush{Buffer: common.GetBuffer()} }
func (*RoutePush) Kind() DataCtrlKind  { return DataCtrlRoutePush }
func (m *RoutePush) Frame() []byte     { return *m.Buffer }
func (m *RoutePush) Release()          { release(&m.Buffer) }

func (m *RoutePush) Seal(prefixes []netip.Prefix) error {
	rentIfNil(&m.Buffer)
	body := 2
	for _, p := range prefixes {
		body += 1 + len(p.Addr().AsSlice()) + 1
	}
	b, err := writeHeader(m.Buffer, DataCtrlRoutePush, body)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(b[dcHeaderSize:dcHeaderSize+2], uint16(len(prefixes)))
	off := dcHeaderSize + 2
	for _, p := range prefixes {
		addr := p.Addr().AsSlice()
		b[off] = byte(len(addr))
		off++
		copy(b[off:off+len(addr)], addr)
		off += len(addr)
		b[off] = byte(p.Bits())
		off++
	}
	return nil
}

func (m *RoutePush) Open() error {
	b := *m.Buffer
	if len(b) < dcHeaderSize+2 {
		return fmt.Errorf("route-push: short")
	}
	n := int(binary.BigEndian.Uint16(b[dcHeaderSize : dcHeaderSize+2]))
	off := dcHeaderSize + 2
	for i := 0; i < n; i++ {
		if len(b) < off+1 {
			return fmt.Errorf("route-push: truncated at entry %d", i)
		}
		al := int(b[off])
		off++
		if len(b) < off+al+1 {
			return fmt.Errorf("route-push: truncated at entry %d", i)
		}
		off += al + 1
	}
	return nil
}

// Count returns the number of prefixes in the frame.
func (m *RoutePush) Count() int {
	b := *m.Buffer
	if len(b) < dcHeaderSize+2 {
		return 0
	}
	return int(binary.BigEndian.Uint16(b[dcHeaderSize : dcHeaderSize+2]))
}

// ForEach calls fn for every prefix in the frame without allocating a
// slice. Returns early if fn returns false.
func (m *RoutePush) ForEach(fn func(netip.Prefix) bool) {
	b := *m.Buffer
	if len(b) < dcHeaderSize+2 {
		return
	}
	n := int(binary.BigEndian.Uint16(b[dcHeaderSize : dcHeaderSize+2]))
	off := dcHeaderSize + 2
	for i := 0; i < n; i++ {
		al := int(b[off])
		off++
		addr, _ := netip.AddrFromSlice(b[off : off+al])
		off += al
		bits := int(b[off])
		off++
		if !fn(netip.PrefixFrom(addr, bits)) {
			return
		}
	}
}

// Prefixes materializes the wire list as a slice (allocates).
func (m *RoutePush) Prefixes() []netip.Prefix {
	out := make([]netip.Prefix, 0, m.Count())
	m.ForEach(func(p netip.Prefix) bool { out = append(out, p); return true })
	return out
}

// RouteAck is empty-body: "got the last RoutePush".
type RouteAck struct{ Buffer *[]byte }

func NewRouteAck() *RouteAck         { return &RouteAck{Buffer: common.GetBuffer()} }
func (*RouteAck) Kind() DataCtrlKind { return DataCtrlRouteAck }
func (m *RouteAck) Frame() []byte    { return *m.Buffer }
func (m *RouteAck) Release()         { release(&m.Buffer) }
func (m *RouteAck) Seal() error {
	rentIfNil(&m.Buffer)
	_, err := writeHeader(m.Buffer, DataCtrlRouteAck, 0)
	return err
}
func (*RouteAck) Open() error { return nil }

// --------------- Shutdown ---------------

// ShutdownReason categorizes why the operator is dropping the session.
type ShutdownReason uint8

const (
	ShutdownGoingAway   ShutdownReason = 0 // routine drain (deploy / rollover)
	ShutdownPolicy      ShutdownReason = 1 // admin / auth revoked
	ShutdownPrefixGone  ShutdownReason = 2 // routing entry deleted
	ShutdownUnspecified ShutdownReason = 0xFF
)

// Shutdown asks the client to close the connection. Body: reason(1).
type Shutdown struct {
	Buffer *[]byte
	Reason *ShutdownReason // pointer view into Buffer[2]
}

func NewShutdown() *Shutdown         { return &Shutdown{Buffer: common.GetBuffer()} }
func (*Shutdown) Kind() DataCtrlKind { return DataCtrlShutdown }
func (m *Shutdown) Frame() []byte    { return *m.Buffer }
func (m *Shutdown) Release()         { release(&m.Buffer); m.Reason = nil }

func (m *Shutdown) Seal(reason ShutdownReason) error {
	rentIfNil(&m.Buffer)
	b, err := writeHeader(m.Buffer, DataCtrlShutdown, 1)
	if err != nil {
		return err
	}
	b[dcHeaderSize] = byte(reason)
	m.Reason = (*ShutdownReason)(&b[dcHeaderSize])
	return nil
}

func (m *Shutdown) Open() error {
	b := *m.Buffer
	if len(b) < dcHeaderSize+1 {
		return fmt.Errorf("shutdown: short")
	}
	m.Reason = (*ShutdownReason)(&b[dcHeaderSize])
	return nil
}

// --------------- Stats ---------------

// Stats is a periodic client -> operator counter snapshot.
// Body wire layout: txBytes(8) + rxBytes(8) + rttMicros(4).
type Stats struct {
	Buffer *[]byte

	tx  *[8]byte // BE uint64 view
	rx  *[8]byte // BE uint64 view
	rtt *[4]byte // BE uint32 view
}

func NewStats() *Stats             { return &Stats{Buffer: common.GetBuffer()} }
func (*Stats) Kind() DataCtrlKind  { return DataCtrlStats }
func (m *Stats) Frame() []byte     { return *m.Buffer }
func (m *Stats) Release()          { release(&m.Buffer); m.tx = nil; m.rx = nil; m.rtt = nil }

func (m *Stats) Seal(tx, rx uint64, rttMicros uint32) error {
	rentIfNil(&m.Buffer)
	b, err := writeHeader(m.Buffer, DataCtrlStats, 8+8+4)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint64(b[dcHeaderSize:dcHeaderSize+8], tx)
	binary.BigEndian.PutUint64(b[dcHeaderSize+8:dcHeaderSize+16], rx)
	binary.BigEndian.PutUint32(b[dcHeaderSize+16:dcHeaderSize+20], rttMicros)
	m.bindViews()
	return nil
}

func (m *Stats) Open() error {
	b := *m.Buffer
	if len(b) < dcHeaderSize+20 {
		return fmt.Errorf("stats: short %d", len(b))
	}
	m.bindViews()
	return nil
}

func (m *Stats) bindViews() {
	b := *m.Buffer
	m.tx = (*[8]byte)(b[dcHeaderSize : dcHeaderSize+8])
	m.rx = (*[8]byte)(b[dcHeaderSize+8 : dcHeaderSize+16])
	m.rtt = (*[4]byte)(b[dcHeaderSize+16 : dcHeaderSize+20])
}

// TxBytes reads the tx counter through the pointer view.
func (m *Stats) TxBytes() uint64 { return binary.BigEndian.Uint64(m.tx[:]) }

// RxBytes reads the rx counter through the pointer view.
func (m *Stats) RxBytes() uint64 { return binary.BigEndian.Uint64(m.rx[:]) }

// RTTMicros reads the RTT through the pointer view.
func (m *Stats) RTTMicros() uint32 { return binary.BigEndian.Uint32(m.rtt[:]) }

// SetTxBytes mutates Buffer through the pointer view.
func (m *Stats) SetTxBytes(v uint64) { binary.BigEndian.PutUint64(m.tx[:], v) }

// SetRxBytes mutates Buffer through the pointer view.
func (m *Stats) SetRxBytes(v uint64) { binary.BigEndian.PutUint64(m.rx[:], v) }

// SetRTTMicros mutates Buffer through the pointer view.
func (m *Stats) SetRTTMicros(v uint32) { binary.BigEndian.PutUint32(m.rtt[:], v) }
