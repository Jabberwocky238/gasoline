package udp

import (
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol/handshake"
	"github.com/jabberwocky238/gasoline/transport"
)

// peerIncomingCap bounds the per-peer datagram backlog. Sized for ~1 round
// of bench traffic (~7600 packets) to absorb bursts while ReadPacket
// consumes; raise further if your workload sustains > 25k pps.
const peerIncomingCap = 8192

type Listener struct {
	rawConn *net.UDPConn
	mapper  handshake.VNIMapperFn

	// peers is guarded by MutexGuard: map[netip.AddrPort]*virtualPeer
	// Using netip.AddrPort as key avoids per-packet string allocation from remoteAddr.String().
	peers *common.MutexGuard[map[netip.AddrPort]*virtualPeer]

	acceptCh chan acceptResult
	closed   atomic.Bool
}

type virtualPeer struct {
	incoming   chan pooledDatagram
	conn       *Conn
	remoteAddr *net.UDPAddr
}

type acceptResult struct {
	accepted transport.Accepted
}

func NewListener(addr string, mapper handshake.VNIMapperFn) (*Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	rawConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	// Best-effort enlarge OS UDP socket buffers (8 MB).
	_ = rawConn.SetReadBuffer(8 * 1024 * 1024)
	_ = rawConn.SetWriteBuffer(8 * 1024 * 1024)
	l := &Listener{
		rawConn:  rawConn,
		mapper:   mapper,
		peers:    common.WithGuard(make(map[netip.AddrPort]*virtualPeer)),
		acceptCh: make(chan acceptResult, 16),
	}
	go l.readLoop()
	return l, nil
}

// readLoop reads datagrams into pool buffers and demuxes them to virtual peers.
// Inspired by OVS dpif-netdev readLoop: single reader thread, per-flow dispatch.
func (l *Listener) readLoop() {
	for {
		if l.closed.Load() {
			return
		}

		tmp := common.GetBuffer()
		n, remoteAddr, err := l.rawConn.ReadFromUDP((*tmp)[:cap(*tmp)])
		if err != nil {
			common.PutBuffer(tmp)
			return
		}

		dg := pooledDatagram{
			data: (*tmp)[:n],
			buf:  tmp,
		}

		// netip.AddrPort is a value type — zero-alloc map key (vs remoteAddr.String())
		key := remoteAddr.AddrPort()

		// Fast path: existing peer (read lock)
		var vp *virtualPeer
		var exists bool
		l.peers.Read(func(m map[netip.AddrPort]*virtualPeer) {
			vp, exists = m[key]
		})

		if exists {
			select {
			case vp.incoming <- dg:
			default:
				dg.release()
			}
			continue
		}

		// Slow path: new peer (write lock)
		vp = &virtualPeer{
			incoming:   make(chan pooledDatagram, peerIncomingCap),
			remoteAddr: remoteAddr,
		}
		l.peers.Write(func(m *map[netip.AddrPort]*virtualPeer) {
			(*m)[key] = vp
		})

		vp.incoming <- dg

		go l.handshakePeer(vp, key)
	}
}

// handshakePeer runs the gasoline handshake for a new peer.
// On failure, cleans up the peer entry.
func (l *Listener) handshakePeer(vp *virtualPeer, key netip.AddrPort) {
	adapter := newVirtualStreamAdapter(l.rawConn, vp.remoteAddr, vp.incoming)
	auth, err := handshake.ServerHandshake(adapter, l.mapper)
	if err != nil {
		l.peers.Write(func(m *map[netip.AddrPort]*virtualPeer) {
			delete(*m, key)
		})
		close(vp.incoming)
		return
	}

	conn := newVirtualConn(l.rawConn, vp.remoteAddr)
	conn.incoming = vp.incoming
	vp.conn = conn

	l.acceptCh <- acceptResult{accepted: transport.Accepted{
		Conn: conn, VNI: auth.VNI, ClientPub: auth.ClientPub, Session: auth.Session,
		C2SKey: auth.C2SKey, S2CKey: auth.S2CKey,
	}}
}

func (l *Listener) Accept() (transport.Accepted, error) {
	res, ok := <-l.acceptCh
	if !ok {
		return transport.Accepted{}, fmt.Errorf("listener closed")
	}
	return res.accepted, nil
}

func (l *Listener) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return nil
	}
	err := l.rawConn.Close()
	// Close acceptCh so Accept() unblocks.
	// Any in-flight handshakePeer goroutines will recover from the send-on-closed panic
	// via the closed flag check, but since rawConn is closed they will fail the handshake
	// and never reach the send.
	close(l.acceptCh)
	return err
}

func (l *Listener) Addr() string {
	return l.rawConn.LocalAddr().String()
}

func (l *Listener) RemoveConn(addr netip.AddrPort) {
	l.peers.Write(func(m *map[netip.AddrPort]*virtualPeer) {
		delete(*m, addr)
	})
}
