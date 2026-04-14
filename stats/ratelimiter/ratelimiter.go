package ratelimiter

import (
	"sync"
	"time"

	"github.com/jabberwocky238/gasoline/common"
)

// Rule defines a rate limit for a VNet.
type Rule struct {
	BytesPerSecond uint64 // 0 = unlimited
}

// bucket tracks token-bucket state for one VNet.
type bucket struct {
	mu         sync.Mutex
	tokens     float64
	capacity   float64
	rate       float64 // tokens per nanosecond
	lastRefill time.Time
}

func (b *bucket) allow(n uint64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastRefill)
	b.tokens += b.rate * float64(elapsed.Nanoseconds())
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	b.lastRefill = now

	cost := float64(n)
	if b.tokens < cost {
		return false
	}
	b.tokens -= cost
	return true
}

// RateLimiter manages per-VNI rate limits using token buckets.
type RateLimiter struct {
	mu      sync.RWMutex
	rules   map[common.VNI]*Rule
	buckets map[common.VNI]*bucket
}

func New() *RateLimiter {
	return &RateLimiter{
		rules:   make(map[common.VNI]*Rule),
		buckets: make(map[common.VNI]*bucket),
	}
}

// SetRule sets the rate limit for a VNI. Pass BytesPerSecond=0 to remove the limit.
func (rl *RateLimiter) SetRule(vni common.VNI, rule *Rule) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rule == nil || rule.BytesPerSecond == 0 {
		delete(rl.rules, vni)
		delete(rl.buckets, vni)
		return
	}
	rl.rules[vni] = rule
	cap := float64(rule.BytesPerSecond) * 2 // allow 2-second burst
	rl.buckets[vni] = &bucket{
		tokens:     cap,
		capacity:   cap,
		rate:       float64(rule.BytesPerSecond) / 1e9,
		lastRefill: time.Now(),
	}
}

// GetRule returns the current rule for a VNI, or nil if unlimited.
func (rl *RateLimiter) GetRule(vni common.VNI) *Rule {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return rl.rules[vni]
}

// Allow checks if n bytes can pass for the given VNI.
// Returns true if allowed (or no rule set).
func (rl *RateLimiter) Allow(vni common.VNI, n uint64) bool {
	rl.mu.RLock()
	b, ok := rl.buckets[vni]
	rl.mu.RUnlock()
	if !ok {
		return true
	}
	return b.allow(n)
}

// Remove cleans up a VNI's rule and bucket.
func (rl *RateLimiter) Remove(vni common.VNI) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.rules, vni)
	delete(rl.buckets, vni)
}

// AllRules returns all current rules.
func (rl *RateLimiter) AllRules() map[common.VNI]*Rule {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	result := make(map[common.VNI]*Rule, len(rl.rules))
	for k, v := range rl.rules {
		result[k] = v
	}
	return result
}
