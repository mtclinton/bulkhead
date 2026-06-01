// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// Backend is one cloud provider for the paid 'api' route (ADR-0002). Each implementation
// owns ONLY its own state — its file-sourced key and its pre-validated base — plus the
// shared no-redirect HTTP client. No backend can read another's key, and selection hands
// a request to exactly one backend, so a key is only ever sent to its own validated host.
type Backend interface {
	Name() string // "anthropic" | "openai" | "gemini"; non-secret, for logs/header
	Configured() bool
	Proxy(ctx context.Context, w http.ResponseWriter, req *ChatRequest)
}

// openAICompatBackend serves any provider that speaks the OpenAI chat-completions wire
// format: OpenAI natively, and Gemini via its OpenAI-compatible endpoint
// (generativelanguage.googleapis.com/v1beta/openai). They differ only in base, chatPath
// and key; name distinguishes them in logs/headers/errors.
type openAICompatBackend struct {
	name, base, chatPath, key, model string
	maxTokens                        int
	hc                               *http.Client
}

func (b *openAICompatBackend) Name() string     { return b.name }
func (b *openAICompatBackend) Configured() bool { return b.key != "" }

func (b *openAICompatBackend) Proxy(ctx context.Context, w http.ResponseWriter, req *ChatRequest) {
	if b.key == "" {
		writeError(w, http.StatusServiceUnavailable, b.name+" API key not configured")
		return
	}
	// Re-marshal from the TYPED request (never the raw client body): this strips the
	// bulkhead-only "route" field (it must never leak upstream), clamps max_tokens to the
	// cap (the same denial-of-wallet guard the Anthropic path enforces), and forces
	// stream=false. temperature passes through — OpenAI and Gemini both accept 0..2 (only
	// Anthropic needs the 0..1 clamp).
	out := openAIUpstreamRequest{
		Model:       chooseModel(req.Model, b.model),
		Messages:    req.Messages,
		MaxTokens:   capTokens(req.MaxTokens, b.maxTokens),
		Temperature: req.Temperature,
		Stream:      false,
	}
	payload, err := json.Marshal(out)
	if err != nil {
		log.Printf("%s: marshal request: %v", b.name, err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, b.base+b.chatPath, bytes.NewReader(payload))
	if err != nil {
		log.Printf("%s: build request: %v", b.name, err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	hreq.Header.Set("content-type", "application/json")
	hreq.Header.Set("Authorization", "Bearer "+b.key)

	resp, err := b.hc.Do(hreq)
	if err != nil {
		log.Printf("%s: upstream unreachable: %v", b.name, err)
		writeError(w, http.StatusBadGateway, "upstream API unavailable")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		log.Printf("%s: upstream error status=%d body=%s", b.name, resp.StatusCode, strings.TrimSpace(string(rb)))
		writeError(w, resp.StatusCode, "upstream API error")
		return
	}
	// Upstream is already OpenAI-shaped; copy through verbatim, capped.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, maxResponseBytes))
}

// capTokens applies the per-provider max_tokens cap (denial-of-wallet guard).
func capTokens(want, limit int) int {
	if want <= 0 {
		want = defaultMaxTokens
	}
	if limit > 0 && want > limit {
		want = limit
	}
	return want
}

// chooseModel passes the client's model through when no per-provider override is set (the
// documented seam for per-provider model maps); otherwise forces the override.
func chooseModel(client, override string) string {
	if override != "" {
		return override
	}
	return client
}

// newNoRedirectClient is the single HTTP client shared by proxyLocal and every backend.
// It NEVER follows redirects: Go does not strip custom auth headers (x-api-key /
// Authorization) on a cross-host 30x, so a redirect could exfiltrate a key. No backend
// legitimately redirects, so stopping at the first response is safe.
func newNoRedirectClient() *http.Client {
	return &http.Client{
		Timeout: 120 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
