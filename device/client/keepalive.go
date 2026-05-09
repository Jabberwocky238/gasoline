package client

import (
	"math/rand"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/transport"
)

// Keepalive emits periodic keepalive frames on a transport.Conn and records
// replies observed via NotifyReply. One Keepalive per connection.
//
// Wire protocol: see common.EtherTypeKeepalive.
// Timer cadence: uniform random in [minInterval, maxInterval), re-rolled
// after every tick.
type Keepalive struct {
	conn    transport.Conn
	selfMAC common.VMAC

	minInterval time.Duration
	maxInterval time.Duration

	ctx *common.GasolineGeneralContext // child of the Client's Gactx; carries logger + cancel

	mu       sync.Mutex
	lastSent time.Time
	lastRecv time.Time
	sent     uint64
	recv     uint64
}

// NewKeepalive constructs a keepalive loop for conn. Default cadence is 10–15s.
// parent is the Client's Gactx; a child scope is derived for Stop() and the
// logger inherits the parent fields (vni, vmac, ...) plus component=keepalive.
func NewKeepalive(parent *common.GasolineGeneralContext, conn transport.Conn, selfMAC common.VMAC) *Keepalive {
	return &Keepalive{
		conn:        conn,
		selfMAC:     selfMAC,
		minInterval: 10 * time.Second,
		maxInterval: 15 * time.Second,
		ctx:         parent.Child(log.Fields{"component": "keepalive"}),
	}
}

// Start launches the ticker goroutine.
func (k *Keepalive) Start() { go k.loop() }

// Stop halts the ticker.
func (k *Keepalive) Stop() { k.ctx.Cancel() }

// NotifyReply records that a keepalive reply was observed on the ingress path.
func (k *Keepalive) NotifyReply() {
	k.mu.Lock()
	k.lastRecv = time.Now()
	k.recv++
	k.mu.Unlock()
}

// Stats returns (sent, recv, lastSent, lastRecv) for inspection.
func (k *Keepalive) Stats() (uint64, uint64, time.Time, time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.sent, k.recv, k.lastSent, k.lastRecv
}

func (k *Keepalive) loop() {
	for {
		d := k.nextInterval()
		t := time.NewTimer(d)
		select {
		case <-k.ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		if err := k.sendOnce(); err != nil {
			k.ctx.Logger().Debugf("keepalive: send: %v", err)
		}
	}
}

func (k *Keepalive) sendOnce() error {
	frame := common.BuildKeepaliveRequest(k.selfMAC)
	if err := k.conn.WritePacket(frame); err != nil {
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
