package client

import (
	"math/rand"
	"sync"
	"time"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/transport"
)

// Keepalive periodically writes a no-op packet to the transport so the
// underlying connection (TCP, QUIC, etc.) stays alive on idle paths.
//
// Wire format: a minimal IP packet with version field set to 3, which
// is reserved/invalid. The operator data plane silently drops it; no
// other client would interpret it as a real frame either.
//
// Since the operator drops these silently, we expect no reply — the
// keepalive is fire-and-forget.
type Keepalive struct {
	conn transport.Conn

	minInterval time.Duration
	maxInterval time.Duration

	lctx *common.LogContext

	mu       sync.Mutex
	lastSent time.Time
	sent     uint64
}

// NewKeepalive constructs a keepalive loop for conn. Default cadence is 10–15s.
// parent is the Client's LogContext; a child scope is derived for Stop().
func NewKeepalive(parent *common.LogContext, conn transport.Conn) *Keepalive {
	return &Keepalive{
		conn:        conn,
		minInterval: 10 * time.Second,
		maxInterval: 15 * time.Second,
		lctx:        parent.WithField("component", "keepalive"),
	}
}

// Start launches the ticker goroutine.
func (k *Keepalive) Start() { go k.loop() }

// Stop halts the ticker.
func (k *Keepalive) Stop() { k.lctx.Cancel() }

// Stats returns (sent, lastSent) for inspection.
func (k *Keepalive) Stats() (uint64, time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.sent, k.lastSent
}

func (k *Keepalive) loop() {
	for {
		d := k.nextInterval()
		t := time.NewTimer(d)
		select {
		case <-k.lctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		if err := k.sendOnce(); err != nil {
			k.lctx.Log().Debugf("send: %v", err)
		}
	}
}

// buildKeepalivePacket returns a 20-byte IP-shaped header whose first
// byte's high nibble (the version field) is 3. Operators drop it.
func buildKeepalivePacket() []byte {
	pkt := make([]byte, 20)
	pkt[0] = 0x30 // version=3, IHL=0
	return pkt
}

func (k *Keepalive) sendOnce() error {
	if err := k.conn.WritePacket(buildKeepalivePacket()); err != nil {
		return err
	}
	k.mu.Lock()
	k.lastSent = time.Now()
	k.sent++
	k.mu.Unlock()
	return nil
}

func (k *Keepalive) nextInterval() time.Duration {
	span := k.maxInterval - k.minInterval
	if span <= 0 {
		return k.minInterval
	}
	return k.minInterval + time.Duration(rand.Int63n(int64(span)))
}
