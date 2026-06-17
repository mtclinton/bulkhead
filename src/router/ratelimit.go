// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"sync"
	"time"
)

// rateLimiter is a token bucket bounding the VOLUME of paid (RouteAPI) calls — the denial-of-wallet
// residual the per-request tier gate leaves open (ADR-0002; security-review R7). decide() bounds
// whether ONE request is paid; this bounds how MANY, so a compromised agent looping threshold-length
// requests is refused once the budget is spent, BEFORE any upstream paid call. It is GLOBAL (not
// per-peer): a single-purpose appliance bounds its TOTAL paid spend, which avoids keying on the
// transient DynamicUser uids agents run as. A nil *rateLimiter means unlimited (the default).
type rateLimiter struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	refill   float64          // tokens per second
	last     time.Time        // last refill instant
	clock    func() time.Time // injectable so tests can drive refill deterministically
}

// newRateLimiter returns a limiter of perMin tokens/minute (burst capacity = perMin), or nil when
// perMin <= 0 (the default — unlimited, zero behaviour change; the operator opts in to a cap).
func newRateLimiter(perMin int) *rateLimiter {
	if perMin <= 0 {
		return nil
	}
	return &rateLimiter{
		tokens:   float64(perMin),
		capacity: float64(perMin),
		refill:   float64(perMin) / 60.0,
		last:     time.Now(),
		clock:    time.Now,
	}
}

// allow consumes one token if available (refilling by elapsed time first) and returns true; it
// returns false (deny) when the budget is exhausted. Thread-safe — the router serves concurrent
// requests. A nil receiver allows (an absent limiter never throttles).
func (l *rateLimiter) allow() bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	if elapsed := now.Sub(l.last).Seconds(); elapsed > 0 {
		l.tokens += elapsed * l.refill
		if l.tokens > l.capacity {
			l.tokens = l.capacity
		}
		l.last = now
	}
	if l.tokens >= 1 {
		l.tokens--
		return true
	}
	return false
}
