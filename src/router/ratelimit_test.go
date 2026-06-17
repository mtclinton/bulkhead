// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestRateLimiterTokenBucket (R7): the bucket allows a burst up to capacity, denies once exhausted,
// and refills by elapsed time; perMin<=0 yields nil (unlimited) and a nil receiver always allows.
func TestRateLimiterTokenBucket(t *testing.T) {
	var nl *rateLimiter
	if !nl.allow() {
		t.Fatal("nil limiter must allow (unlimited)")
	}
	if newRateLimiter(0) != nil || newRateLimiter(-5) != nil {
		t.Fatal("perMin<=0 must yield nil (unlimited)")
	}

	now := time.Unix(1000, 0)
	l := newRateLimiter(3) // 3/min, capacity 3
	l.clock = func() time.Time { return now }
	l.last = now // align the refill baseline with the injected clock (newRateLimiter seeds real time.Now)

	for i := 0; i < 3; i++ {
		if !l.allow() {
			t.Fatalf("burst token %d must be allowed", i+1)
		}
	}
	if l.allow() {
		t.Fatal("4th call must be denied (budget exhausted, no time elapsed)")
	}

	now = now.Add(20 * time.Second) // 3/min = 0.05 tok/s * 20s = 1 token refilled
	if !l.allow() {
		t.Fatal("after a 20s refill, one call must be allowed")
	}
	if l.allow() {
		t.Fatal("only one token refilled in 20s; the next must be denied")
	}
}

// TestPaidRateCapRefusesFlood (R7): an end-to-end handleChat flood of paid (RouteAPI) requests is
// refused with 429 once the per-minute budget is spent, while the upstream is hit only up to the cap.
// This is the denial-of-wallet bound the per-request tier gate alone does not provide.
func TestPaidRateCapRefusesFlood(t *testing.T) {
	upstreamHits := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"x","choices":[{"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	defer up.Close()

	hc := newNoRedirectClient()
	cfg := config{Threshold: 1, DefaultRoute: RouteLocal, PaidRatePerMin: 2} // cap 2 paid calls/min
	s := newServer(cfg, map[string]Backend{"openai": oaiBackend("openai", up.URL, "/v1/chat/completions", "sk-oai", hc)}, hc)

	// model=gpt-* -> selectProvider=openai; promptLen >= Threshold(1) -> RouteAPI (no client downgrade).
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"a long enough prompt"}]}`
	call := func() int {
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body)))
		return rec.Code
	}

	if c := call(); c != http.StatusOK {
		t.Fatalf("paid call 1: want 200, got %d", c)
	}
	if c := call(); c != http.StatusOK {
		t.Fatalf("paid call 2: want 200, got %d", c)
	}
	if c := call(); c != http.StatusTooManyRequests {
		t.Fatalf("paid call 3: want 429 (rate cap), got %d", c)
	}
	if upstreamHits != 2 {
		t.Fatalf("the rate-capped call must NOT reach upstream: upstreamHits=%d want 2", upstreamHits)
	}

	// A LOCAL (free) request is never throttled even after the paid budget is spent. It routes to
	// LlamaURL (unset here), so it fails to reach a backend — but with a 502/5xx, never a 429.
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"route":"local","model":"gpt-4","messages":[{"role":"user","content":"x"}]}`)))
	if rec.Code == http.StatusTooManyRequests {
		t.Fatalf("a local/free request must never be rate-capped, got 429")
	}
}
