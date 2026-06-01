// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func f64(v float64) *float64 { return &v }

func configDefaults() config {
	return config{
		Listen: "127.0.0.1:0", LlamaURL: "http://127.0.0.1:8081", Threshold: 2000,
		DefaultRoute: RouteLocal, ClaudeModel: "claude-sonnet-4-6",
		AnthropicBase: "https://api.anthropic.com", AnthropicVersion: "2023-06-01",
		AnthropicMaxTokens: 4096,
	}
}

func doChat(t *testing.T, s *server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	return rr
}

// anthropicOnly builds a server whose only paid backend is Anthropic (the v1 shape), so
// the existing tests exercise the api route via the Anthropic provider unchanged.
func anthropicOnly(cfg config, key string) *server {
	hc := newNoRedirectClient()
	p := map[string]Backend{"anthropic": &anthropicBackend{
		key: key, base: cfg.AnthropicBase, version: cfg.AnthropicVersion,
		model: cfg.ClaudeModel, maxTokens: cfg.AnthropicMaxTokens, hc: hc,
	}}
	return newServer(cfg, p, hc)
}

func TestDecideDowngradeOnly(t *testing.T) {
	short := []ChatMessage{{Role: "user", Content: "hi"}}
	long := []ChatMessage{{Role: "user", Content: strings.Repeat("x", 2500)}}
	cases := []struct {
		name      string
		req       *ChatRequest
		threshold int
		want      Route
	}{
		{"short->local", &ChatRequest{Messages: short}, 2000, RouteLocal},
		{"long->api", &ChatRequest{Messages: long}, 2000, RouteAPI},
		{"explicit api on short is IGNORED (no forced paid tier)", &ChatRequest{Route: RouteAPI, Messages: short}, 2000, RouteLocal},
		{"explicit local on long downgrades", &ChatRequest{Route: RouteLocal, Messages: long}, 2000, RouteLocal},
		{"boundary equal->api", &ChatRequest{Messages: []ChatMessage{{Content: strings.Repeat("x", 2000)}}}, 2000, RouteAPI},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := decide(c.req, c.threshold, RouteLocal); got.Route != c.want {
				t.Fatalf("decide = %s, want %s (reason %q)", got.Route, c.want, got.Reason)
			}
		})
	}
}

func TestToAnthropic(t *testing.T) {
	req := &ChatRequest{
		Model: "local-3b",
		Messages: []ChatMessage{
			{Role: "system", Content: "be brief"},
			{Role: "system", Content: "be kind"},
			{Role: "tool", Content: "tool noise"}, // unknown role -> folded to user
			{Role: "user", Content: "hello"},
		},
	}
	a := toAnthropic(req, "claude-sonnet-4-6", 4096)
	if a.Model != "claude-sonnet-4-6" {
		t.Fatalf("model not overridden: %s", a.Model)
	}
	if a.System != "be brief\n\nbe kind" {
		t.Fatalf("system join wrong: %q", a.System)
	}
	if len(a.Messages) != 2 || a.Messages[0].Role != "user" || a.Messages[1].Role != "user" {
		t.Fatalf("role folding wrong: %+v", a.Messages)
	}
	if a.MaxTokens != defaultMaxTokens {
		t.Fatalf("max tokens default wrong: %d", a.MaxTokens)
	}
}

func TestToAnthropicClamps(t *testing.T) {
	hot := f64(2.0)
	a := toAnthropic(&ChatRequest{Messages: []ChatMessage{{Role: "user", Content: "x"}}, MaxTokens: 999999, Temperature: hot}, "m", 4096)
	if a.MaxTokens != 4096 {
		t.Fatalf("max_tokens not clamped: %d", a.MaxTokens)
	}
	if a.Temperature == nil || *a.Temperature != 1.0 {
		t.Fatalf("temperature not clamped to 1.0: %v", a.Temperature)
	}
	cold := f64(-0.5)
	a = toAnthropic(&ChatRequest{Messages: []ChatMessage{{Role: "user", Content: "x"}}, Temperature: cold}, "m", 4096)
	if a.Temperature == nil || *a.Temperature != 0.0 {
		t.Fatalf("negative temperature not clamped to 0: %v", a.Temperature)
	}
}

func TestFromAnthropic(t *testing.T) {
	ar := &anthropicResponse{
		ID: "msg_1", Model: "claude-sonnet-4-6",
		Content:    []anthropicContentBlock{{Type: "text", Text: "Hello"}, {Type: "text", Text: " world"}},
		StopReason: "max_tokens",
		Usage:      anthropicUsage{InputTokens: 10, OutputTokens: 5},
	}
	r := fromAnthropic(ar)
	if len(r.Choices) != 1 || r.Choices[0].Message.Content != "Hello world" {
		t.Fatalf("content join wrong: %+v", r.Choices)
	}
	if r.Choices[0].FinishReason != "length" {
		t.Fatalf("finish reason: %s", r.Choices[0].FinishReason)
	}
	if r.Usage.TotalTokens != 15 || r.Object != "chat.completion" {
		t.Fatalf("usage/object wrong: %+v", r)
	}
}

func TestSourceURL(t *testing.T) {
	old := BuildCommit
	defer func() { BuildCommit = old }()
	BuildCommit = "dev"
	if got := sourceURL(); got != sourceRepo {
		t.Fatalf("dev url: %s", got)
	}
	BuildCommit = "abc123"
	if got := sourceURL(); got != sourceRepo+"/tree/abc123" {
		t.Fatalf("commit url: %s", got)
	}
}

func TestValidateAnthropicBase(t *testing.T) {
	cases := []struct {
		base     string
		insecure bool
		wantErr  bool
	}{
		{"https://api.anthropic.com", false, false},
		{"http://api.anthropic.com", false, true}, // not https
		{"https://evil.example.com", false, true}, // wrong host
		{"http://127.0.0.1:8080", true, false},    // opt-out for tests/proxy
		{"://bad", false, true},                   // unparseable
	}
	for _, c := range cases {
		err := validateAnthropicBase(c.base, c.insecure)
		if (err != nil) != c.wantErr {
			t.Fatalf("validateAnthropicBase(%q, %v) err=%v, wantErr=%v", c.base, c.insecure, err, c.wantErr)
		}
	}
}

func TestLoadAnthropicKey(t *testing.T) {
	dir := t.TempDir()
	credDir := filepath.Join(dir, "creds")
	if err := os.MkdirAll(credDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(credDir, "anthropic-api-key"), []byte("  sk-ant-REDACTED\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", credDir)
	t.Setenv("ANTHROPIC_API_KEY_FILE", "")
	if k, err := loadAnthropicKey(); err != nil || k != "sk-ant-REDACTED" {
		t.Fatalf("cred dir load: %q err=%v", k, err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	f := filepath.Join(dir, "key.txt")
	if err := os.WriteFile(f, []byte("sk-ant-FILE"), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANTHROPIC_API_KEY_FILE", f)
	if k, err := loadAnthropicKey(); err != nil || k != "sk-ant-FILE" {
		t.Fatalf("file load: %q err=%v", k, err)
	}
	t.Setenv("ANTHROPIC_API_KEY_FILE", "")
	if _, err := loadAnthropicKey(); err == nil {
		t.Fatal("expected error when no key present")
	}
}

func TestHandleChatLocal(t *testing.T) {
	llama := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("llama path %s", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "hello") {
			t.Errorf("body not forwarded: %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"local-pong"}}]}`))
	}))
	defer llama.Close()

	cfg := configDefaults()
	cfg.LlamaURL = llama.URL
	rr := doChat(t, anthropicOnly(cfg, ""), `{"messages":[{"role":"user","content":"hello"}]}`)
	if rr.Code != 200 {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-Bulkhead-Route") != "local" {
		t.Fatalf("route header %s", rr.Header().Get("X-Bulkhead-Route"))
	}
	if rr.Header().Get("X-Source-Code") == "" {
		t.Fatal("missing X-Source-Code header")
	}
	if !strings.Contains(rr.Body.String(), "local-pong") {
		t.Fatalf("body %s", rr.Body.String())
	}
}

func TestHandleChatAPI(t *testing.T) {
	anth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Errorf("anthropic path %s", r.URL.Path)
		}
		if r.Header.Get("x-api-key") != "sk-ant-TEST" {
			t.Errorf("key header %q", r.Header.Get("x-api-key"))
		}
		if r.Header.Get("anthropic-version") == "" {
			t.Errorf("missing anthropic-version")
		}
		var ar anthropicRequest
		_ = json.NewDecoder(r.Body).Decode(&ar)
		if ar.System != "sys" {
			t.Errorf("system not translated: %q", ar.System)
		}
		_, _ = w.Write([]byte(`{"id":"msg_x","model":"claude-sonnet-4-6","content":[{"type":"text","text":"api-pong"}],"stop_reason":"end_turn","usage":{"input_tokens":3,"output_tokens":2}}`))
	}))
	defer anth.Close()

	cfg := configDefaults()
	cfg.AnthropicBase = anth.URL
	cfg.Threshold = 0 // force the api route via the length rule (route field can't force api)
	rr := doChat(t, anthropicOnly(cfg, "sk-ant-TEST"),
		`{"messages":[{"role":"system","content":"sys"},{"role":"user","content":"hi"}]}`)
	if rr.Code != 200 {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-Bulkhead-Route") != "api" {
		t.Fatalf("route header %s", rr.Header().Get("X-Bulkhead-Route"))
	}
	var out ChatResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Choices[0].Message.Content != "api-pong" {
		t.Fatalf("content %q", out.Choices[0].Message.Content)
	}
}

func TestHandleChatAPINoKey(t *testing.T) {
	cfg := configDefaults()
	cfg.Threshold = 0
	rr := doChat(t, anthropicOnly(cfg, ""), `{"messages":[{"role":"user","content":"hi"}]}`)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body %s", rr.Code, rr.Body.String())
	}
}

func TestStreamRejected(t *testing.T) {
	rr := doChat(t, anthropicOnly(configDefaults(), ""),
		`{"stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for stream, got %d", rr.Code)
	}
}

// A client tagging route=api must NOT reach the paid tier (denial-of-wallet guard).
func TestRouteCannotForceAPI(t *testing.T) {
	rr := doChat(t, anthropicOnly(configDefaults(), "sk-ant-TEST"),
		`{"route":"api","messages":[{"role":"user","content":"hi"}]}`)
	if rr.Header().Get("X-Bulkhead-Route") != "local" {
		t.Fatalf("client forced paid tier: route=%s", rr.Header().Get("X-Bulkhead-Route"))
	}
}

// The key must never be forwarded across a redirect to another host.
func TestNoRedirectKeyLeak(t *testing.T) {
	var evilHits int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&evilHits, 1)
		if r.Header.Get("x-api-key") != "" {
			t.Errorf("KEY LEAKED to redirect target: %q", r.Header.Get("x-api-key"))
		}
	}))
	defer evil.Close()
	anth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL, http.StatusFound)
	}))
	defer anth.Close()

	cfg := configDefaults()
	cfg.AnthropicBase = anth.URL
	cfg.Threshold = 0
	rr := doChat(t, anthropicOnly(cfg, "sk-ant-LEAKME"),
		`{"messages":[{"role":"user","content":"hi"}]}`)
	if n := atomic.LoadInt32(&evilHits); n != 0 {
		t.Fatalf("redirect was followed (%d hits) — key may have leaked", n)
	}
	if rr.Code == 200 {
		t.Fatalf("expected upstream error surfaced, got 200")
	}
}

func TestBodyTooLarge(t *testing.T) {
	big := strings.Repeat("a", (8<<20)+1024)
	rr := doChat(t, anthropicOnly(configDefaults(), ""), big)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rr.Code)
	}
}
