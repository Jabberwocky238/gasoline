package common

import (
	"context"

	log "github.com/sirupsen/logrus"
)

// GasolineGeneralContext is gasoline's enriched context. It embeds a standard context.GasolineGeneralContext
// (so it can be passed anywhere a plain ctx is expected) and carries a cancel
// function plus a structured logrus entry. Components retrieve the logger via
// the explicit Logger() getter instead of a typed ctx-value lookup, keeping
// access type-safe and discoverable.
type GasolineGeneralContext struct {
	context.Context
	cancel context.CancelFunc
	logger *log.Entry
}

// NewGasolineCtx wraps parent with a cancel scope and a logger. If parent is nil,
// context.Background is used. If logger is nil, a fresh entry bound to
// logrus.StandardLogger is used.
func NewGasolineCtx(parent context.Context, logger *log.Entry) *GasolineGeneralContext {
	if parent == nil {
		parent = context.Background()
	}
	if logger == nil {
		logger = log.NewEntry(log.StandardLogger())
	}
	ctx, cancel := context.WithCancel(parent)
	return &GasolineGeneralContext{Context: ctx, cancel: cancel, logger: logger}
}

// Cancel tears down this Gactx and every Gactx derived from it via Child.
func (g *GasolineGeneralContext) Cancel() {
	if g == nil || g.cancel == nil {
		return
	}
	g.cancel()
}

// Logger returns the attached logrus entry. Never nil.
func (g *GasolineGeneralContext) Logger() *log.Entry { return g.logger }

// Child returns a Gactx whose cancel is scoped below g and whose logger has
// `fields` merged in. Canceling g cascades to every child.
func (g *GasolineGeneralContext) Child(fields log.Fields) *GasolineGeneralContext {
	ctx, cancel := context.WithCancel(g.Context)
	return &GasolineGeneralContext{
		Context: ctx,
		cancel:  cancel,
		logger:  g.logger.WithFields(fields),
	}
}
