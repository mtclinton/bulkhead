// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
)

const (
	maxRequestBytes  = 8 << 20  // 8 MiB inbound cap
	maxResponseBytes = 32 << 20 // 32 MiB upstream response cap
)

type server struct {
	cfg         config
	providers   map[string]Backend // paid 'api' backends, by canonical name
	defaultName string             // provider for an api request whose model matches no prefix
	http        *http.Client       // shared no-redirect client (proxyLocal + every backend)
	audit       *auditLog          // ADR-0027 signed routing-decision chain; nil in unit tests (audit skipped)
	paidLimiter *rateLimiter       // R7: paid-call volume cap; nil = unlimited (default)
}

func newServer(cfg config, providers map[string]Backend, hc *http.Client) *server {
	def := cfg.APIProvider
	if def == "" {
		def = "anthropic"
	}
	return &server{cfg: cfg, providers: providers, defaultName: def, http: hc, paidLimiter: newRateLimiter(cfg.PaidRatePerMin)}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/chat/completions", s.handleChat)
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /source", s.handleSource)
	return s.withSourceHeader(mux)
}

// withSourceHeader adds the AGPL section 13 source-offer header to every
// response, so the running build always advertises its corresponding source.
func (s *server) withSourceHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Source-Code", sourceURL())
		next.ServeHTTP(w, r)
	})
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "build": BuildCommit})
}

func (s *server) handleSource(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, sourceURL(), http.StatusFound)
}

func (s *server) handleChat(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		log.Printf("read body: %v", err)
		writeError(w, http.StatusBadRequest, "could not read request body")
		return
	}
	var req ChatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		log.Printf("invalid request JSON: %v", err)
		writeError(w, http.StatusBadRequest, "invalid JSON request body")
		return
	}
	if len(req.Messages) == 0 {
		writeError(w, http.StatusBadRequest, "messages must not be empty")
		return
	}
	if req.Stream {
		// Streaming translation is not implemented yet; fail loudly rather than
		// silently returning a non-streamed body the client did not expect.
		writeError(w, http.StatusBadRequest, "streaming responses are not supported")
		return
	}

	d := decide(&req, s.cfg.Threshold, s.cfg.DefaultRoute)
	w.Header().Set("X-Bulkhead-Route", string(d.Route))

	// R7 (security review): bound paid-call VOLUME (denial-of-wallet). decide() bounds whether ONE
	// request is paid; this bounds how MANY. A compromised agent looping threshold-length requests is
	// refused once the per-minute budget is spent — BEFORE any upstream paid call and before the routing
	// commit (a refused request is not a routing decision, so it is logged, not signed). Off by default
	// (paidLimiter nil => allow). The local/free route is never throttled.
	if d.Route == RouteAPI && !s.paidLimiter.allow() {
		log.Printf("route=api REFUSED: paid-call rate cap exceeded (%d/min)", s.cfg.PaidRatePerMin)
		writeError(w, http.StatusTooManyRequests, "paid-call rate limit exceeded")
		return
	}

	// ADR-0027: record the routing decision in the signed chain BEFORE acting on it. The provider (the
	// outbound destination for an api route) is selectProvider(model) — deterministic at decide-time, so
	// it is bound into the SAME record. FAIL-CLOSED: if the append fails we refuse the request rather than
	// route un-audited (the broker's precedent — accountability is load-bearing, not best-effort).
	provider := ""
	if d.Route == RouteAPI {
		provider = selectProvider(req.Model, s.defaultName)
	}
	if s.audit != nil {
		if err := s.audit.recordRoute(string(d.Route), d.Reason, req.Model, promptLen(&req), provider); err != nil {
			log.Printf("audit: routing-decision append FAILED: %v", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
	log.Printf("route=%s reason=%q model=%q promptlen=%d", d.Route, d.Reason, req.Model, promptLen(&req))

	switch d.Route {
	case RouteAPI:
		// Pick WHICH paid provider serves this api request. selectProvider runs ONLY
		// here, after decide() already returned RouteAPI — it chooses the vendor, never
		// the tier, so it cannot turn a short prompt into a paid call.
		p, ok := s.providers[provider]
		if !ok {
			writeError(w, http.StatusServiceUnavailable, "api provider unavailable")
			return
		}
		w.Header().Set("X-Bulkhead-Provider", p.Name())
		log.Printf("api provider=%s model=%q", p.Name(), req.Model)
		p.Proxy(r.Context(), w, &req)
	default:
		s.proxyLocal(r.Context(), w, body)
	}
}

// proxyLocal forwards the original request body to the local llama.cpp server's
// OpenAI-compatible endpoint and returns its response. llama-server ignores the
// bulkhead-only "route" field.
func (s *server) proxyLocal(ctx context.Context, w http.ResponseWriter, body []byte) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.LlamaURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		log.Printf("local proxy: build request: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		log.Printf("local inference unreachable: %v", err)
		writeError(w, http.StatusBadGateway, "local inference backend unavailable")
		return
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, maxResponseBytes))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError returns a generic, client-safe message. Internal detail (upstream
// bodies, transport errors, parser errors) is logged server-side, never echoed.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"message": msg}})
}
