package client

import (
	"sync"

	tun "github.com/jabberwocky238/gasoline/tun"
)

type ClientConfig struct {
	tun struct {
		address string
	}
}
type Client struct {
	mu     sync.Mutex
	tun    *tun.Tun
	dialer Dialer
}

func New(options ClientConfig) (*Client, error) {
	tun, err := tun.New("gasoline-tun", options.tun.address)
	if err != nil {
		return nil, err
	}
	return &Client{tun: tun}, nil
}

func (c *Client) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.start()
}

func (c *Client) start() error {
	// 1. Start the tun interface
	if err := c.tun.Start(); err != nil {
		return err
	}
	// 2. Start the client
	go func() {

	}()
	return nil
}
