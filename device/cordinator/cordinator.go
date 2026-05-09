package cordinator

import (
	"context"

	log "github.com/sirupsen/logrus"
)

// Cordinator is an empty shell. Behavior to be filled in.
type Cordinator struct {
	ctx    context.Context
	cancel context.CancelFunc
	log    *log.Logger
}

// New returns an unstarted Cordinator.
func New() *Cordinator {
	ctx, cancel := context.WithCancel(context.Background())
	return &Cordinator{
		ctx:    ctx,
		cancel: cancel,
		log:    log.New(),
	}
}

// Start is a no-op until told otherwise.
func (c *Cordinator) Start() error { return nil }

// Close releases the Cordinator's context.
func (c *Cordinator) Close() error {
	c.cancel()
	return nil
}
