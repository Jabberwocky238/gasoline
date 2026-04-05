package client

import (
	"context"

	"github.com/jabberwocky238/gasoline/common"
)

type DialerConfig struct {
	ctx       context.Context
	endpoint  string
	transport common.Transport
}

type Dialer struct {
	cfg DialerConfig
	ctx context.Context
}

func New(cfg DialerConfig) (*Dialer, error) {
	return &Dialer{cfg: cfg, ctx: cfg.ctx}, nil
}

func (d *Dialer) Dial() error {
	return nil
}
