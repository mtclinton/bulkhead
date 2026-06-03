// SPDX-License-Identifier: AGPL-3.0-only
package main

// The OpenAI-compatible chat contract, MIRRORED from src/router/types.go (the router is
// package main, so it can't be imported). The agent only needs this subset; a contract test
// pins shape parity with the router. Route is the bulkhead extension; the agent always sends
// RouteLocal so it is a free-tier workload by construction (the router's decide() ignores a
// client-forced paid tier, so the agent can never drive denial-of-wallet).
type Route string

const RouteLocal Route = "local"

type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatRequest struct {
	Model     string        `json:"model,omitempty"`
	Messages  []ChatMessage `json:"messages"`
	MaxTokens int           `json:"max_tokens,omitempty"`
	Route     Route         `json:"route,omitempty"`
}

type ChatResponse struct {
	ID      string       `json:"id"`
	Object  string       `json:"object"`
	Created int64        `json:"created"`
	Model   string       `json:"model"`
	Choices []ChatChoice `json:"choices"`
}

type ChatChoice struct {
	Index        int         `json:"index"`
	Message      ChatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}
