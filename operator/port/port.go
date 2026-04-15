// Package port wraps the operator's inter-operator UDP socket with a
// platform-aware batch-I/O API, layered on top of the wireguard-go Bind
// abstraction (see wireguard-conn.go, bind_std.go, bind_windows.go).
package port

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"

	wgconn "github.com/jabberwocky238/gasoline/operator/port/wgconn"
)

// maxPacketSize is the per-slot RX buffer cap. Sized for jumbo-ish UDP;
// matches wireguard-go's MaxMessageSize / device defaults.
const maxPacketSize = 2048

// Conn is the operator's UDP port abstraction. All methods are safe for
// concurrent callers unless noted otherwise.
//
// Zero-alloc contract: callers provide the buffer slices; the implementation
// must not retain them past the call return.
type Conn interface {
	// WriteBatch sends each element of bufs as one UDP datagram to addr.
	// Returns the number of datagrams successfully sent (0 ≤ n ≤ len(bufs))
	// and any error from the last attempted send.
	WriteBatch(bufs [][]byte, addr netip.AddrPort) (int, error)

	// ReadBatch fills bufs with up to len(bufs) received datagrams. Returns
	// the number of datagrams received n. For each i in [0, n): sizes[i] is
	// the datagram length written to bufs[i][:sizes[i]]; addrs[i] is the
	// source endpoint.
	ReadBatch(bufs [][]byte, sizes []int, addrs []netip.AddrPort) (int, error)

	// LocalAddr returns the socket's bound address.
	LocalAddr() netip.AddrPort

	// BatchSize reports the effective per-syscall cap. Linux: IdealBatchSize.
	// Windows / darwin / *bsd: 1.
	BatchSize() int

	// Close releases the underlying socket. Concurrent pending ReadBatch /
	// WriteBatch calls return an error.
	Close() error
}

// Open binds wgconn.StdNetBind on the host:port parsed from addr and
// wraps it in a Conn. host is honoured — passing "127.0.0.1:N" binds
// loopback only (avoids the Windows Defender Firewall popup that
// wildcard binds trigger), an IPv4 literal binds v4 only, an IPv6
// literal binds v6 only, and an empty host (":N") preserves the
// original dual-stack 0.0.0.0:N + [::]:N behaviour.
func Open(addr string) (Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("port: parse addr %q: %w", addr, err)
	}
	p64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("port: parse port %q: %w", portStr, err)
	}
	return openBind(wgconn.NewStdNetBindOn(host), uint16(p64))
}

// rxSlot is one batch of receive buffers handed off between a recv goroutine
// (which calls ReceiveFunc into it) and ReadBatch (which copies out and
// returns the slot to the free pool).
type rxSlot struct {
	bufs  [][]byte
	sizes []int
	eps   []wgconn.Endpoint
	n     int
	err   error
}

// bindConn adapts a wireguard Bind (callback / multi-receive-fn API) to the
// pull-based Conn interface. One goroutine per ReceiveFunc pumps batches
// into rxCh; ReadBatch consumes one batch per call.
type bindConn struct {
	bind      wgconn.Bind
	batchSize int
	localAddr netip.AddrPort

	rxCh   chan *rxSlot
	freeCh chan *rxSlot

	closeOnce sync.Once
	closeErr  error
	closed    atomic.Bool
	wg        sync.WaitGroup
}

const slotsPerFn = 32

func openBind(b wgconn.Bind, listenPort uint16) (*bindConn, error) {
	fns, actualPort, err := b.Open(listenPort)
	if err != nil {
		return nil, err
	}
	bs := b.BatchSize()
	if bs <= 0 {
		bs = 1
	}

	totalSlots := len(fns) * slotsPerFn
	if totalSlots == 0 {
		totalSlots = 1
	}
	c := &bindConn{
		bind:      b,
		batchSize: bs,
		localAddr: netip.AddrPortFrom(netip.IPv6Unspecified(), actualPort),
		rxCh:      make(chan *rxSlot, totalSlots),
		freeCh:    make(chan *rxSlot, totalSlots),
	}
	for i := 0; i < totalSlots; i++ {
		s := &rxSlot{
			bufs:  make([][]byte, bs),
			sizes: make([]int, bs),
			eps:   make([]wgconn.Endpoint, bs),
		}
		for j := range s.bufs {
			s.bufs[j] = make([]byte, maxPacketSize)
		}
		c.freeCh <- s
	}
	c.wg.Add(len(fns))
	for _, fn := range fns {
		go c.recvLoop(fn)
	}
	return c, nil
}

func (c *bindConn) recvLoop(fn wgconn.ReceiveFunc) {
	defer c.wg.Done()
	for {
		slot, ok := <-c.freeCh
		if !ok {
			return
		}
		for j := range slot.bufs {
			slot.bufs[j] = slot.bufs[j][:maxPacketSize]
			slot.sizes[j] = 0
			slot.eps[j] = nil
		}
		n, err := fn(slot.bufs, slot.sizes, slot.eps)
		slot.n = n
		slot.err = err
		c.rxCh <- slot
		if err != nil {
			return
		}
	}
}

func (c *bindConn) BatchSize() int            { return c.batchSize }
func (c *bindConn) LocalAddr() netip.AddrPort { return c.localAddr }

func (c *bindConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.closeErr = c.bind.Close()
		c.wg.Wait()
		close(c.rxCh)
	})
	return c.closeErr
}

func (c *bindConn) WriteBatch(bufs [][]byte, addr netip.AddrPort) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(bufs) == 0 {
		return 0, nil
	}
	// Callers (vxlan.Plane) often hand us v4-mapped-v6 addresses produced by
	// net.ResolveUDPAddr("udp", "127.0.0.1:p") → "[::ffff:127.0.0.1]:p".
	// StdNetBind would route those to its v6 socket, which Go opens with
	// IPV6_V6ONLY=1 → sendmmsg returns ENETUNREACH and the packet is dropped.
	// Unmap up front so v4 destinations always traverse the v4 socket.
	addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
	ep, err := c.bind.ParseEndpoint(addr.String())
	if err != nil {
		return 0, err
	}
	bs := c.batchSize
	sent := 0
	for sent < len(bufs) {
		end := sent + bs
		if end > len(bufs) {
			end = len(bufs)
		}
		if err := c.bind.Send(bufs[sent:end], ep); err != nil {
			return sent, err
		}
		sent = end
	}
	return sent, nil
}

func (c *bindConn) ReadBatch(bufs [][]byte, sizes []int, addrs []netip.AddrPort) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	if len(sizes) < len(bufs) || len(addrs) < len(bufs) {
		return 0, fmt.Errorf("port: sizes/addrs shorter than bufs")
	}
	slot, ok := <-c.rxCh
	if !ok {
		return 0, net.ErrClosed
	}
	n := slot.n
	if n > len(bufs) {
		n = len(bufs)
	}
	for i := 0; i < n; i++ {
		sz := slot.sizes[i]
		dst := bufs[i]
		if sz > len(dst) {
			sz = len(dst)
		}
		copy(dst[:sz], slot.bufs[i][:sz])
		sizes[i] = sz
		if slot.eps[i] != nil {
			addrs[i] = endpointAddrPort(slot.eps[i])
		} else {
			addrs[i] = netip.AddrPort{}
		}
	}
	err := slot.err
	select {
	case c.freeCh <- slot:
	default:
	}
	if n == 0 && err != nil {
		return 0, err
	}
	return n, nil
}

// endpointAddrPort recovers a netip.AddrPort from a wireguard Endpoint.
// Both StdNetEndpoint and WinRingEndpoint render their destination via
// DstToString as a form netip.ParseAddrPort accepts.
func endpointAddrPort(ep wgconn.Endpoint) netip.AddrPort {
	if ap, err := netip.ParseAddrPort(ep.DstToString()); err == nil {
		return ap
	}
	return netip.AddrPort{}
}
