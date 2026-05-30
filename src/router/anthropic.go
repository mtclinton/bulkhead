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

const defaultMaxTokens = 1024

// toAnthropic translates an OpenAI chat request into an Anthropic Messages
// request. System messages are concatenated into the top-level system field;
// assistant messages pass through; every other role (user, tool, or unknown) is
// folded to "user" so an unexpected role cannot trigger an upstream 400. The
// model is overridden with the configured Claude model — the client's model
// name targets the local tier. max_tokens is bounded by cap (denial-of-wallet
// guard) and temperature is clamped into Anthropic's accepted 0..1 range.
func toAnthropic(req *ChatRequest, model string, maxTokensCap int) anthropicRequest {
	var system []string
	var msgs []anthropicMessage
	for _, m := range req.Messages {
		switch m.Role {
		case "system":
			system = append(system, m.Content)
		case "assistant":
			msgs = append(msgs, anthropicMessage{Role: "assistant", Content: m.Content})
		default:
			msgs = append(msgs, anthropicMessage{Role: "user", Content: m.Content})
		}
	}

	maxTok := req.MaxTokens
	if maxTok <= 0 {
		maxTok = defaultMaxTokens
	}
	if maxTokensCap > 0 && maxTok > maxTokensCap {
		maxTok = maxTokensCap
	}

	var temp *float64
	if req.Temperature != nil {
		t := *req.Temperature
		if t < 0 {
			t = 0
		}
		if t > 1 { // OpenAI permits up to 2; Anthropic rejects > 1
			t = 1
		}
		temp = &t
	}

	return anthropicRequest{
		Model:       model,
		System:      strings.Join(system, "\n\n"),
		Messages:    msgs,
		MaxTokens:   maxTok,
		Temperature: temp,
	}
}

// fromAnthropic translates an Anthropic Messages response into an OpenAI chat
// response.
func fromAnthropic(ar *anthropicResponse) ChatResponse {
	var text strings.Builder
	for _, b := range ar.Content {
		if b.Type == "text" {
			text.WriteString(b.Text)
		}
	}
	finish := "stop"
	if ar.StopReason == "max_tokens" {
		finish = "length"
	}
	return ChatResponse{
		ID:      ar.ID,
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   ar.Model,
		Choices: []ChatChoice{{
			Index:        0,
			Message:      ChatMessage{Role: "assistant", Content: text.String()},
			FinishReason: finish,
		}},
		Usage: &Usage{
			PromptTokens:     ar.Usage.InputTokens,
			CompletionTokens: ar.Usage.OutputTokens,
			TotalTokens:      ar.Usage.InputTokens + ar.Usage.OutputTokens,
		},
	}
}

// proxyAnthropic translates the request, calls the Anthropic Messages API with
// the file-sourced key, and translates the response back to OpenAI shape. The
// key is sent only as the x-api-key header, never logged, and the client never
// redirects (see newServer). Upstream error detail is logged server-side, not
// echoed to the caller.
func (s *server) proxyAnthropic(ctx context.Context, w http.ResponseWriter, req *ChatRequest) {
	if s.key == "" {
		writeError(w, http.StatusServiceUnavailable, "Anthropic API key not configured")
		return
	}
	ar := toAnthropic(req, s.cfg.ClaudeModel, s.cfg.AnthropicMaxTokens)
	if len(ar.Messages) == 0 {
		writeError(w, http.StatusBadRequest, "no user or assistant messages")
		return
	}
	payload, _ := json.Marshal(ar)

	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.AnthropicBase+"/v1/messages", bytes.NewReader(payload))
	if err != nil {
		log.Printf("anthropic: build request: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	hreq.Header.Set("content-type", "application/json")
	hreq.Header.Set("x-api-key", s.key)
	hreq.Header.Set("anthropic-version", s.cfg.AnthropicVersion)

	resp, err := s.http.Do(hreq)
	if err != nil {
		log.Printf("anthropic: upstream unreachable: %v", err)
		writeError(w, http.StatusBadGateway, "upstream API unavailable")
		return
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode != http.StatusOK {
		log.Printf("anthropic: upstream error status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(rb)))
		writeError(w, resp.StatusCode, "upstream API error")
		return
	}
	var aresp anthropicResponse
	if err := json.Unmarshal(rb, &aresp); err != nil {
		log.Printf("anthropic: decode response: %v", err)
		writeError(w, http.StatusBadGateway, "invalid upstream response")
		return
	}
	writeJSON(w, http.StatusOK, fromAnthropic(&aresp))
}
