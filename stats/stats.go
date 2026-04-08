package stats

import (
	"github.com/jabberwocky238/gasoline/stats/query"
	"github.com/jabberwocky238/gasoline/stats/ratelimiter"
	"github.com/jabberwocky238/gasoline/stats/recorder"
)

// Engine is the top-level stats engine that ties together
// traffic recording, rate limiting, and the HTTP query API.
type Engine struct {
	Recorder    *recorder.Recorder
	RateLimiter *ratelimiter.RateLimiter
	API         *query.Server
}

// New creates a stats engine. Pass listenAddr="" to disable the HTTP API.
func New(listenAddr string) *Engine {
	rec := recorder.New()
	rl := ratelimiter.New()
	var api *query.Server
	if listenAddr != "" {
		api = query.New(listenAddr, rec, rl)
	}
	return &Engine{
		Recorder:    rec,
		RateLimiter: rl,
		API:         api,
	}
}

// Start launches the HTTP API server (non-blocking).
func (e *Engine) Start() error {
	if e.API != nil {
		return e.API.Start()
	}
	return nil
}

// Close shuts down the HTTP API server.
func (e *Engine) Close() error {
	if e.API != nil {
		return e.API.Close()
	}
	return nil
}
