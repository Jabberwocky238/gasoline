package udp

import (
	"fmt"
	"net"
	"sync"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport"
)

type Listener struct {
	rawConn  *net.UDPConn
	resolver auth.AuthResolver
	configFn protocol.ConfigFunc

	mu    sync.RWMutex
	peers map[string]*virtualPeer // remote addr → peer state

	acceptCh chan acceptResult
	closeCh  chan struct{}
}

type virtualPeer struct {
	incoming   chan []byte // datagrams routed here by muxer
	conn       *Conn      // set after handshake completes
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
		peers:    make(map[string]*virtualPeer),
		acceptCh: make(chan acceptResult, 16),
		closeCh:  make(chan struct{}),
	}
	go l.readLoop()
	return l, nil
}

// readLoop reads datagrams and demuxes them to virtual peers.
func (l *Listener) readLoop() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-l.closeCh:
			return
		default:
		}

		n, remoteAddr, err := l.rawConn.ReadFromUDP(buf[:])
		if err != nil {
			select {
			case <-l.closeCh:
			default:
			}
			return
		}

		key := remoteAddr.String()
		data := make([]byte, n)
		copy(data, buf[:n])

		l.mu.RLock()
		vp, exists := l.peers[key]
		l.mu.RUnlock()

		if exists {
			select {
			case vp.incoming <- data:
			default:
			}
			continue
		}

		// New peer — create virtual peer and start handshake
		vp = &virtualPeer{
			incoming:   make(chan []byte, 64),
			remoteAddr: remoteAddr,
		}
		l.mu.Lock()
		l.peers[key] = vp
		l.mu.Unlock()

		vp.incoming <- data

		go func(vp *virtualPeer) {
			// Handshake over stream adapter
			adapter := newVirtualStreamAdapter(l.rawConn, vp.remoteAddr, vp.incoming)
			result, err := protocol.ServerHandshake(adapter, l.resolver, l.configFn)
			if err != nil {
				l.mu.Lock()
				delete(l.peers, vp.remoteAddr.String())
				l.mu.Unlock()
				close(vp.incoming)
				return
			}

			// Handshake done — create data conn backed by the same incoming channel
			conn := newVirtualConn(l.rawConn, vp.remoteAddr, result.Keypair)
			conn.incoming = vp.incoming // reuse the channel
			vp.conn = conn

			l.acceptCh <- acceptResult{conn: conn, result: result}
		}(vp)
	}
}

func (l *Listener) Accept() (transport.Conn, *protocol.HandshakeResult, error) {
	select {
	case <-l.closeCh:
		return nil, nil, fmt.Errorf("listener closed")
	case res := <-l.acceptCh:
		return res.conn, res.result, nil
	}
}

func (l *Listener) Close() error {
	close(l.closeCh)
	return l.rawConn.Close()
}

func (l *Listener) Addr() string {
	return l.rawConn.LocalAddr().String()
}

func (l *Listener) RemoveConn(remoteAddr string) {
	l.mu.Lock()
	delete(l.peers, remoteAddr)
	l.mu.Unlock()
}
