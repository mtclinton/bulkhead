// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
)

// runMockChat is a TEST/DEMO-only OpenAI-compatible endpoint — NOT for production (its systemd
// unit is never [Install]-enabled; it is started only by the demo/harness). It scripts the
// agent through the headline demo by counting how many OBSERVATION turns the transcript already
// carries: turn 0 -> fetch the (public) target [gets E2-denied]; after the deny -> request_egress
// public; then retry the fetch; then FINAL. The agent binary is byte-identical to production —
// only BULKHEAD_ROUTER_URL points here instead of the real router, exactly the indirection the
// router itself uses for httptest.
func runMockChat() {
	addr := envOr("BULKHEAD_MOCKCHAT_ADDR", "127.0.0.1:8088")
	target := envOr("BULKHEAD_MOCKCHAT_TARGET", "https://api.anthropic.com/")

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var req ChatRequest
		_ = json.Unmarshal(raw, &req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ChatResponse{
			Object:  "chat.completion",
			Model:   "mockchat",
			Choices: []ChatChoice{{Message: ChatMessage{Role: "assistant", Content: mockReply(req.Messages, target)}}},
		})
	})

	log.Printf("mockchat: canned /v1/chat/completions on %s (target %s) — TEST/DEMO ONLY", addr, target)
	log.Fatal((&http.Server{Addr: addr, Handler: mux}).ListenAndServe())
}

// mockReply scripts the headline demo by the count of OBSERVATION turns already in the
// transcript: fetch the target (E2-denied) -> request_egress public -> retry fetch -> FINAL.
func mockReply(msgs []ChatMessage, target string) string {
	obs := 0
	for _, m := range msgs {
		if m.Role == "user" && strings.HasPrefix(m.Content, "OBSERVATION:") {
			obs++
		}
	}
	switch obs {
	case 0:
		return "TOOL fetch " + target
	case 1:
		return "TOOL request_egress public"
	case 2:
		return "TOOL fetch " + target
	default:
		return "FINAL finished after the operator decided on the egress request"
	}
}
