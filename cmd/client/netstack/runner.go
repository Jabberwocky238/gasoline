package netstack

import (
	"errors"
	"io"
	"sync"
)

// PacketReader is the minimal contract the Runner needs to pull raw IP
// packets from the OS TUN device. gasoline/tun.Tun satisfies this out of the
// box — but accepting the narrower interface keeps netstack unit-testable
// without a real TUN.
type PacketReader interface {
	Read(buf []byte) (int, error)
}

// Runner wires a TUN reader into Stack.HandleTunInbound in a loop. It is
// purely a convenience — callers that already have their own read loop can
// ignore this and invoke HandleTunInbound directly.
//
// Lifecycle: NewRunner → Start → (running) → Close. Close cancels the loop
// by closing the TUN reader, so the caller must ensure `r` returns from Read
// after close.
type Runner struct {
	stack *Stack
	r     PacketReader
	mtu   int

	mu      sync.Mutex
	started bool
	stopped chan struct{}
}

// NewRunner creates an inert runner. Start to begin reading.
func NewRunner(s *Stack, r PacketReader) *Runner {
	mtu := int(s.cfg.mtu())
	if mtu <= 0 {
		mtu = 1500
	}
	return &Runner{
		stack:   s,
		r:       r,
		mtu:     mtu + 40, // slack for optional IP options / IPv6 ext hdrs
		stopped: make(chan struct{}),
	}
}

// Start spawns the read loop. It is safe to call once; calling again returns
// an error.
func (r *Runner) Start() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return errors.New("netstack: runner already started")
	}
	r.started = true
	go r.loop()
	return nil
}

// Done returns a channel that closes once the read loop has exited (because
// the TUN reader returned an error, typically from Close).
func (r *Runner) Done() <-chan struct{} { return r.stopped }

func (r *Runner) loop() {
	defer close(r.stopped)
	buf := make([]byte, r.mtu)
	for {
		n, err := r.r.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			return
		}
		if n <= 0 {
			continue
		}
		// HandleTunInbound copies what it needs before returning, so we can
		// reuse buf on the next iteration.
		r.stack.HandleTunInbound(buf[:n])
	}
}
