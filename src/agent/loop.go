// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

const observationCap = 2 << 10 // re-appended observations are truncated so a large body can't blow the next prompt

func systemPrompt() string {
	return strings.Join([]string{
		"You are a bulkhead agent. Accomplish the task using EXACTLY ONE action per turn.",
		"Reply with a SINGLE line, exactly one of:",
		"  TOOL fetch <url>               -- HTTP GET a URL",
		"  TOOL request_egress <classes>  -- ask the operator to widen this agent's egress (e.g. public)",
		"  FINAL <text>                   -- you are done; give the answer",
		"If a fetch is DENIED by the egress policy, you may request_egress to ask a human for access, then retry.",
		"Output nothing but that one TOOL or FINAL line.",
	}, "\n")
}

// runLoop is the bounded perceive->decide->act loop. It terminates on a FINAL directive, on the
// step cap, or on the context deadline — whichever first. A malformed/hostile reply or a tool
// error just costs a bounded step (security never depends on the model behaving).
func runLoop(ctx context.Context, routerURL, task string, maxSteps int, reg map[string]Tool) (string, error) {
	msgs := []ChatMessage{
		{Role: "system", Content: systemPrompt()},
		{Role: "user", Content: "Task: " + task},
	}
	for step := 1; step <= maxSteps; step++ {
		if ctx.Err() != nil {
			return "", fmt.Errorf("deadline exceeded before step %d", step)
		}
		reply, err := chat(ctx, routerURL, msgs)
		if err != nil {
			return "", fmt.Errorf("step %d inference: %w", step, err)
		}
		d, ok := parse(reply)
		if !ok {
			log.Printf("agent: step %d unparseable reply %q", step, truncate(reply, 160))
			msgs = append(msgs,
				ChatMessage{Role: "assistant", Content: reply},
				ChatMessage{Role: "user", Content: "Emit exactly one line: TOOL <name> <arg> or FINAL <text>."})
			continue
		}
		if d.Kind == "final" {
			log.Printf("agent: step %d FINAL %q", step, truncate(d.Arg, 200))
			return d.Arg, nil
		}
		obs := dispatch(ctx, reg, d)
		log.Printf("agent: step %d TOOL %s %q -> %s", step, d.Name, truncate(d.Arg, 80), truncate(obs, 200))
		msgs = append(msgs,
			ChatMessage{Role: "assistant", Content: reply},
			ChatMessage{Role: "user", Content: "OBSERVATION: " + obs})
	}
	return "", fmt.Errorf("step budget (%d) exhausted without FINAL", maxSteps)
}

// dispatch validates + runs one directive, returning a truncated observation (never an error —
// a bad tool/arg/run feeds back so the model can adjust within the bounded budget).
func dispatch(ctx context.Context, reg map[string]Tool, d Directive) string {
	tool, known := reg[d.Name]
	switch {
	case !known:
		return "ERROR: unknown tool " + d.Name
	default:
		if err := tool.Validate(d.Arg); err != nil {
			return "ERROR: bad arg for " + d.Name + ": " + err.Error()
		}
		o, err := tool.Run(ctx, d.Arg)
		if err != nil {
			return "ERROR: " + d.Name + ": " + err.Error()
		}
		return truncate(o, observationCap)
	}
}

func chat(ctx context.Context, routerURL string, msgs []ChatMessage) (string, error) {
	body, _ := json.Marshal(ChatRequest{Messages: msgs, MaxTokens: 256, Route: RouteLocal})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(routerURL, "/")+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	hc := &http.Client{Timeout: 60 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("router HTTP %d: %s", resp.StatusCode, truncate(string(raw), 160))
	}
	var cr ChatResponse
	if err := json.Unmarshal(raw, &cr); err != nil {
		return "", err
	}
	if len(cr.Choices) == 0 {
		return "", fmt.Errorf("router returned no choices")
	}
	return cr.Choices[0].Message.Content, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
