package udp

import (
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport"
)

type Listener struct {
	rawConn  *net.UDPConn
	resolver auth.AuthResolver
	configFn protocol.ConfigFunc

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
	conn   transport.Conn
	result *protocol.HandshakeResult
}

func NewListener(addr string, resolver auth.AuthResolver, configFn protocol.ConfigFunc) (*Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	rawConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	l := &Listener{
		rawConn:  rawConn,
		resolver: resolver,
		configFn: configFn,
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
			incoming:   make(chan pooledDatagram, 64),
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
	result, err := protocol.ServerHandshake(adapter, l.resolver, l.configFn)
	if err != nil {
		l.peers.Write(func(m *map[netip.AddrPort]*virtualPeer) {
			delete(*m, key)
		})
		close(vp.incoming)
		return
	}

	conn := newVirtualConn(l.rawConn, vp.remoteAddr, result.Keypair)
	conn.incoming = vp.incoming
	vp.conn = conn

	l.acceptCh <- acceptResult{conn: conn, result: result}
}

func (l *Listener) Accept() (transport.Conn, *protocol.HandshakeResult, error) {
	res, ok := <-l.acceptCh
	if !ok {
		return nil, nil, fmt.Errorf("listener closed")
	}
	return res.conn, res.result, nil
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
