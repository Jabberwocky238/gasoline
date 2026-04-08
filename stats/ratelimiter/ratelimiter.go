package ratelimiter

import (
	"sync"
	"time"
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

// RateLimiter manages per-VNet rate limits using token buckets.
type RateLimiter struct {
	mu      sync.RWMutex
	rules   map[[16]byte]*Rule   // vnetID → rule
	buckets map[[16]byte]*bucket // vnetID → bucket
}

func New() *RateLimiter {
	return &RateLimiter{
		rules:   make(map[[16]byte]*Rule),
		buckets: make(map[[16]byte]*bucket),
	}
}

// SetRule sets the rate limit for a VNet. Pass BytesPerSecond=0 to remove the limit.
func (rl *RateLimiter) SetRule(vnetID [16]byte, rule *Rule) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rule == nil || rule.BytesPerSecond == 0 {
		delete(rl.rules, vnetID)
		delete(rl.buckets, vnetID)
		return
	}
	rl.rules[vnetID] = rule
	cap := float64(rule.BytesPerSecond) * 2 // allow 2-second burst
	rl.buckets[vnetID] = &bucket{
		tokens:     cap,
		capacity:   cap,
		rate:       float64(rule.BytesPerSecond) / 1e9,
		lastRefill: time.Now(),
	}
}

// GetRule returns the current rule for a VNet, or nil if unlimited.
func (rl *RateLimiter) GetRule(vnetID [16]byte) *Rule {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return rl.rules[vnetID]
}

// Allow checks if n bytes can pass for the given VNet.
// Returns true if allowed (or no rule set).
func (rl *RateLimiter) Allow(vnetID [16]byte, n uint64) bool {
	rl.mu.RLock()
	b, ok := rl.buckets[vnetID]
	rl.mu.RUnlock()
	if !ok {
		return true
	}
	return b.allow(n)
}

// Remove cleans up a VNet's rule and bucket.
func (rl *RateLimiter) Remove(vnetID [16]byte) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.rules, vnetID)
	delete(rl.buckets, vnetID)
}

// AllRules returns all current rules.
func (rl *RateLimiter) AllRules() map[[16]byte]*Rule {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	result := make(map[[16]byte]*Rule, len(rl.rules))
	for k, v := range rl.rules {
		result[k] = v
	}
	return result
}
