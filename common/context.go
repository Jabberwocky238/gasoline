package common

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
)

// LogContext bundles a cancellable context.Context with a logrus
// *Entry. Cancellation semantics are exactly context.WithCancel:
//
//   - Cancel() drops this node and every descendant.
//   - A descendant cancelling itself does NOT affect the parent.
//   - The parent cancelling propagates Done() to every descendant.
//
// LogContext implements context.Context so it can be passed wherever
// a stdlib context is expected.
type LogContext struct {
	ctx    context.Context
	cancel context.CancelFunc
	logger *log.Logger
	log    *log.Entry
}

// NewLogContext returns a fresh root LogContext bound to parent.
// parent may be nil (defaults to context.Background()). logger may be
// nil (defaults to a fresh logrus.New()).
func NewLogContext(parent context.Context, logger *log.Logger) *LogContext {
	if parent == nil {
		parent = context.Background()
	}
	if logger == nil {
		logger = log.New()
	}
	ctx, cancel := context.WithCancel(parent)
	return &LogContext{
		ctx:    ctx,
		cancel: cancel,
		logger: logger,
		log:    logger.WithContext(ctx),
	}
}

// Context returns the underlying stdlib context.
func (c *LogContext) Context() context.Context { return c.ctx }

// Cancel drops this LogContext and every descendant. Idempotent.
func (c *LogContext) Cancel() { c.cancel() }

// Log returns the logrus entry attached here. Mutating it via
// .WithField on the returned value does not affect c.
func (c *LogContext) Log() *log.Entry { return c.log }

// Derive forks a child whose lifetime is bound to c. Cancelling the
// child does not affect c; cancelling c (or any ancestor) cancels the
// child. The log entry is inherited unchanged.
func (c *LogContext) Derive() *LogContext {
	ctx, cancel := context.WithCancel(c.ctx)
	return &LogContext{
		ctx:    ctx,
		cancel: cancel,
		logger: c.logger,
		log:    c.log,
	}
}

// WithField returns a child LogContext (new cancellation scope) whose
// log entry is tagged with (key, value).
func (c *LogContext) WithField(key string, value any) *LogContext {
	ctx, cancel := context.WithCancel(c.ctx)
	return &LogContext{
		ctx:    ctx,
		cancel: cancel,
		logger: c.logger,
		log:    c.log.WithField(key, value),
	}
}

// --------------- context.Context interface ---------------

func (c *LogContext) Deadline() (time.Time, bool) { return c.ctx.Deadline() }
func (c *LogContext) Done() <-chan struct{}       { return c.ctx.Done() }
func (c *LogContext) Err() error                  { return c.ctx.Err() }
func (c *LogContext) Value(key any) any           { return c.ctx.Value(key) }
