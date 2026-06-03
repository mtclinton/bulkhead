// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in              string
		ok              bool
		kind, name, arg string
	}{
		{"TOOL fetch https://x/", true, "tool", "fetch", "https://x/"},
		{"FINAL all done", true, "final", "", "all done"},
		{"sure, here goes:\nTOOL fetch http://a/\nignore", true, "tool", "fetch", "http://a/"}, // first valid line wins
		{"TOOL request_egress public", true, "tool", "request_egress", "public"},
		{"   TOOL   fetch   https://y/  ", true, "tool", "fetch", "https://y/"}, // prose padding
		{"i think the answer is 42", false, "", "", ""},
		{"", false, "", "", ""},
		{"tool fetch x", false, "", "", ""}, // lowercase verb is not a directive (strict verb)
	}
	for _, c := range cases {
		d, ok := parse(c.in)
		if ok != c.ok {
			t.Fatalf("parse(%q) ok=%v, want %v", c.in, ok, c.ok)
		}
		if ok && (d.Kind != c.kind || d.Name != c.name || d.Arg != c.arg) {
			t.Fatalf("parse(%q) = %+v, want {%s %s %q}", c.in, d, c.kind, c.name, c.arg)
		}
	}
}

// scriptedRouter returns a router stub whose reply depends on the OBSERVATION count, and records
// the Route the agent sent (for the denial-of-wallet assertion).
func scriptedRouter(t *testing.T, reply func(obs int) string, gotRoute *string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ChatRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if gotRoute != nil {
			*gotRoute = string(req.Route)
		}
		obs := 0
		for _, m := range req.Messages {
			if strings.HasPrefix(m.Content, "OBSERVATION:") {
				obs++
			}
		}
		_ = json.NewEncoder(w).Encode(ChatResponse{Choices: []ChatChoice{{Message: ChatMessage{Content: reply(obs)}}}})
	}))
}

func TestRunLoopHappyPathAndForcedLocal(t *testing.T) {
	var route string
	srv := scriptedRouter(t, func(obs int) string {
		if obs >= 1 {
			return "FINAL done"
		}
		return "TOOL echo hi"
	}, &route)
	defer srv.Close()

	var ranArg string
	reg := map[string]Tool{"echo": {
		Validate: func(string) error { return nil },
		Run:      func(_ context.Context, a string) (string, error) { ranArg = a; return "echoed " + a, nil },
	}}
	ans, err := runLoop(context.Background(), srv.URL, "say hi", 6, reg)
	if err != nil {
		t.Fatalf("runLoop: %v", err)
	}
	if ans != "done" {
		t.Fatalf("answer = %q, want done", ans)
	}
	if ranArg != "hi" {
		t.Fatalf("tool ran with arg %q, want hi", ranArg)
	}
	if route != "local" {
		t.Fatalf("agent sent route=%q, want local (denial-of-wallet: agent is free-tier by construction)", route)
	}
}

func TestRunLoopMaxStepsTerminates(t *testing.T) {
	srv := scriptedRouter(t, func(int) string { return "TOOL echo loop" }, nil) // never FINAL
	defer srv.Close()
	reg := map[string]Tool{"echo": {Validate: func(string) error { return nil }, Run: func(context.Context, string) (string, error) { return "x", nil }}}
	if _, err := runLoop(context.Background(), srv.URL, "t", 3, reg); err == nil {
		t.Fatal("a never-FINAL loop must terminate at the step cap")
	}
}

func TestRunLoopToolErrorFedBackNotFatal(t *testing.T) {
	srv := scriptedRouter(t, func(obs int) string {
		if obs >= 1 {
			return "FINAL recovered"
		}
		return "TOOL nope x" // unknown tool -> error observation, must not be fatal
	}, nil)
	defer srv.Close()
	ans, err := runLoop(context.Background(), srv.URL, "t", 6, map[string]Tool{})
	if err != nil {
		t.Fatalf("an unknown-tool observation must be fed back, not fatal: %v", err)
	}
	if ans != "recovered" {
		t.Fatalf("answer = %q, want recovered", ans)
	}
}

func TestFetchTool(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("payload"))
	}))
	defer backend.Close()
	ft := toolRegistry()["fetch"]
	if err := ft.Validate("not a url"); err == nil {
		t.Fatal("a non-URL arg must be rejected")
	}
	if err := ft.Validate(backend.URL); err != nil {
		t.Fatalf("a valid URL must validate: %v", err)
	}
	obs, _ := ft.Run(context.Background(), backend.URL)
	if !strings.Contains(obs, "HTTP 200") {
		t.Fatalf("fetch observation = %q, want HTTP 200", obs)
	}
	// A refused connection yields a structured ERROR observation (never a fatal error).
	obs2, err := ft.Run(context.Background(), "http://127.0.0.1:1/")
	if err != nil {
		t.Fatalf("a connect failure must be an observation, not an error: %v", err)
	}
	if !strings.Contains(obs2, "ERROR") && !strings.Contains(obs2, "DENIED") {
		t.Fatalf("refused fetch observation = %q", obs2)
	}
}

func TestRequestEgressEscalation(t *testing.T) {
	rt := toolRegistry()["request_egress"]
	if err := rt.Validate("public"); err != nil {
		t.Fatalf("valid class must validate: %v", err)
	}
	if err := rt.Validate("bogus"); err == nil {
		t.Fatal("a bad egress class must be rejected before any exec")
	}
	dir := t.TempDir()
	old := collectorBin
	defer func() { collectorBin = old }()

	allow := filepath.Join(dir, "collector-allow")
	if err := os.WriteFile(allow, []byte("#!/bin/sh\necho 'OK loopback,other,public'\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	collectorBin = allow
	if obs, _ := rt.Run(context.Background(), "public"); !strings.Contains(obs, "escalation OK") {
		t.Fatalf("operator ALLOW must yield an OK observation, got %q", obs)
	}

	deny := filepath.Join(dir, "collector-deny")
	if err := os.WriteFile(deny, []byte("#!/bin/sh\necho 'ERR deny'\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	collectorBin = deny
	if obs, _ := rt.Run(context.Background(), "public"); !strings.Contains(obs, "ESCALATION DENIED") {
		t.Fatalf("operator DENY must yield ESCALATION DENIED (agent cannot proceed), got %q", obs)
	}
}

// TestDelegateToolCarriesTask: the delegate tool accepts a task tail, and Run hands the task
// to the collector as ONE argv element (so exec never re-splits a multi-word task).
func TestDelegateToolCarriesTask(t *testing.T) {
	dt := toolRegistry()["delegate"]
	if err := dt.Validate("child public the rest is a task"); err != nil {
		t.Fatalf("a suffix+classes+task must validate: %v", err)
	}
	if err := dt.Validate("child"); err == nil {
		t.Fatal("a missing class list must be rejected")
	}
	if err := dt.Validate("child bogus do x"); err == nil {
		t.Fatal("a bad egress class must be rejected before any exec")
	}

	dir := t.TempDir()
	old := collectorBin
	defer func() { collectorBin = old }()
	// dump each argv on its own line so we can assert the task arrived as a SINGLE element
	dump := filepath.Join(dir, "argv-dump")
	if err := os.WriteFile(dump, []byte("#!/bin/sh\nfor a in \"$@\"; do echo \"[$a]\"; done\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	collectorBin = dump
	t.Setenv("BULKHEAD_AGENT_ALLOW_DELEGATE", "1")
	obs, _ := dt.Run(context.Background(), "kid public,loopback do X then Y")
	for _, want := range []string{"[delegate]", "[kid]", "[public,loopback]", "[do X then Y]"} {
		if !strings.Contains(obs, want) {
			t.Fatalf("argv missing %q in:\n%s", want, obs)
		}
	}
	// off-by-default: no opt-in => no exec, a clear refusal
	t.Setenv("BULKHEAD_AGENT_ALLOW_DELEGATE", "")
	if obs, _ := dt.Run(context.Background(), "kid public do x"); !strings.Contains(obs, "disabled") {
		t.Fatalf("delegation must be disabled without the opt-in, got %q", obs)
	}
}

// TestTaskFromCredential: a delegated child reads its task from the systemd credential when
// BULKHEAD_AGENT_TASK is empty; the env always wins if set; absent both yields "".
func TestTaskFromCredential(t *testing.T) {
	t.Setenv("BULKHEAD_AGENT_TASK", "from-env")
	t.Setenv("BULKHEAD_AGENT_TASK_CRED", "agent-task")
	dir := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	if err := os.WriteFile(filepath.Join(dir, "agent-task"), []byte("  do the thing\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if got := resolveTask(); got != "from-env" {
		t.Fatalf("env must win: got %q", got)
	}
	t.Setenv("BULKHEAD_AGENT_TASK", "")
	if got := resolveTask(); got != "do the thing" {
		t.Fatalf("credential fallback (trimmed) = %q, want \"do the thing\"", got)
	}
	t.Setenv("BULKHEAD_AGENT_TASK_CRED", "")
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if got := resolveTask(); got != "" {
		t.Fatalf("absent env + cred => %q, want empty", got)
	}
}

func TestMockReplyScript(t *testing.T) {
	mk := func(obs int) []ChatMessage {
		m := []ChatMessage{{Role: "system", Content: "sys"}, {Role: "user", Content: "Task: t"}}
		for i := 0; i < obs; i++ {
			m = append(m, ChatMessage{Role: "assistant", Content: "x"}, ChatMessage{Role: "user", Content: "OBSERVATION: o"})
		}
		return m
	}
	if r := mockReply(mk(0), "https://t/"); !strings.HasPrefix(r, "TOOL fetch ") {
		t.Fatalf("turn 0 = %q, want a fetch", r)
	}
	if r := mockReply(mk(1), "https://t/"); r != "TOOL request_egress public" {
		t.Fatalf("turn 1 (after deny) = %q, want request_egress public", r)
	}
	if r := mockReply(mk(2), "https://t/"); !strings.HasPrefix(r, "TOOL fetch ") {
		t.Fatalf("turn 2 = %q, want a retried fetch", r)
	}
	if r := mockReply(mk(3), "https://t/"); !strings.HasPrefix(r, "FINAL") {
		t.Fatalf("turn 3 = %q, want FINAL", r)
	}
}

// TestMockReplyOrchestration covers the ADR-0015 parent/child mock branches: a PARENT (ORCH
// task) emits exactly one delegate directive carrying the child task then FINALs; a CHILD
// (FETCH-ONLY task) fetches once then FINALs reporting its observation (no escalation).
func TestMockReplyOrchestration(t *testing.T) {
	mk := func(task string, obs int) []ChatMessage {
		m := []ChatMessage{{Role: "system", Content: "sys"}, {Role: "user", Content: "Task: " + task}}
		for i := 0; i < obs; i++ {
			m = append(m, ChatMessage{Role: "assistant", Content: "x"}, ChatMessage{Role: "user", Content: "OBSERVATION: DENIED: egress blocked"})
		}
		return m
	}
	parentTask := "ORCH childprobe public,loopback,other FETCH-ONLY https://api.anthropic.com/"
	if r := mockReply(mk(parentTask, 0), "https://t/"); r != "TOOL delegate childprobe public,loopback,other FETCH-ONLY https://api.anthropic.com/" {
		t.Fatalf("parent turn 0 = %q, want a delegate directive carrying the child task", r)
	}
	if r := mockReply(mk(parentTask, 1), "https://t/"); !strings.HasPrefix(r, "FINAL") {
		t.Fatalf("parent turn 1 = %q, want FINAL", r)
	}
	if r := mockReply(mk("FETCH-ONLY https://x/", 0), "https://target/"); r != "TOOL fetch https://target/" {
		t.Fatalf("child turn 0 = %q, want a single fetch of the target", r)
	}
	r := mockReply(mk("FETCH-ONLY https://x/", 1), "https://target/")
	if !strings.HasPrefix(r, "FINAL") || !strings.Contains(r, "DENIED") {
		t.Fatalf("child turn 1 = %q, want FINAL echoing the (denied) observation, no escalation", r)
	}
}
