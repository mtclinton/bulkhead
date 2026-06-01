// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func oaiBackend(name, base, chatPath, key string, hc *http.Client) *openAICompatBackend {
	return &openAICompatBackend{name: name, base: base, chatPath: chatPath, key: key, maxTokens: 4096, hc: hc}
}

const openAIShaped = `{"id":"x","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"hi"}}]}`
const anthroShaped = `{"id":"a","model":"claude-x","role":"assistant","content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`

func TestSelectProvider(t *testing.T) {
	for _, c := range []struct{ model, def, want string }{
		{"claude-sonnet-4-6", "anthropic", "anthropic"},
		{"gpt-5", "anthropic", "openai"},
		{"o3-mini", "anthropic", "openai"},
		{"o4-mini", "anthropic", "openai"},
		{"gemini-2.5-pro", "anthropic", "gemini"},
		{"", "anthropic", "anthropic"},           // empty -> default
		{"mystery", "gemini", "gemini"},          // unknown -> configured default
		{"  GPT-4o  ", "anthropic", "openai"},    // case + whitespace insensitive
		{"openrouter", "anthropic", "anthropic"}, // 'o' is NOT a blanket openai prefix
	} {
		if got := selectProvider(c.model, c.def); got != c.want {
			t.Errorf("selectProvider(%q,%q)=%q want %q", c.model, c.def, got, c.want)
		}
	}
}

// TestSelectionCannotForceAPI: the #1 invariant. A short prompt with model=gpt-5 + an
// explicit route=api must still go LOCAL (downgrade-only) and never hit a paid provider.
func TestSelectionCannotForceAPI(t *testing.T) {
	var hits int32
	oai := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(openAIShaped))
	}))
	defer oai.Close()
	cfg := configDefaults()
	cfg.Threshold = 1 << 30 // a short prompt can never reach api via the length rule
	hc := newNoRedirectClient()
	s := newServer(cfg, map[string]Backend{"openai": oaiBackend("openai", oai.URL, "/v1/chat/completions", "sk-oai", hc)}, hc)
	rr := doChat(t, s, `{"model":"gpt-5","route":"api","messages":[{"role":"user","content":"hi"}]}`)
	if got := rr.Header().Get("X-Bulkhead-Route"); got != "local" {
		t.Fatalf("route=%q want local (client must not force the paid tier)", got)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("openai hit %d times — denial-of-wallet hole: model+route forced a paid call", n)
	}
}

// TestOpenAICompatShaping: the upstream gets the right path/auth, the bulkhead-only route
// field is stripped, stream is false, and max_tokens is clamped to the cap.
func TestOpenAICompatShaping(t *testing.T) {
	var path, auth string
	var body map[string]any
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, auth = r.URL.Path, r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		_, _ = w.Write([]byte(openAIShaped))
	}))
	defer up.Close()
	cfg := configDefaults()
	cfg.Threshold = 0 // force api via the LENGTH rule (not the route field)
	hc := newNoRedirectClient()
	b := oaiBackend("openai", up.URL, "/v1/chat/completions", "sk-oai-TEST", hc)
	b.maxTokens = 100
	s := newServer(cfg, map[string]Backend{"openai": b}, hc)
	rr := doChat(t, s, `{"model":"gpt-5","route":"api","max_tokens":9999,"messages":[{"role":"user","content":"hello"}]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d", rr.Code)
	}
	if path != "/v1/chat/completions" {
		t.Errorf("path=%q", path)
	}
	if auth != "Bearer sk-oai-TEST" {
		t.Errorf("auth=%q want Bearer sk-oai-TEST", auth)
	}
	if _, leaked := body["route"]; leaked {
		t.Error("bulkhead-only 'route' field leaked to the upstream")
	}
	if body["stream"] != false {
		t.Errorf("stream=%v want false", body["stream"])
	}
	if mt, _ := body["max_tokens"].(float64); int(mt) != 100 {
		t.Errorf("max_tokens=%v want clamped 100", body["max_tokens"])
	}
	if p := rr.Header().Get("X-Bulkhead-Provider"); p != "openai" {
		t.Errorf("X-Bulkhead-Provider=%q want openai", p)
	}
}

func TestGeminiPathShaping(t *testing.T) {
	var path string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_, _ = w.Write([]byte(openAIShaped))
	}))
	defer up.Close()
	cfg := configDefaults()
	cfg.Threshold = 0
	hc := newNoRedirectClient()
	// mirror prod: Gemini's /v1beta/openai prefix lives in the base, chatPath=/chat/completions
	s := newServer(cfg, map[string]Backend{"gemini": oaiBackend("gemini", up.URL+"/v1beta/openai", "/chat/completions", "sk-gem", hc)}, hc)
	doChat(t, s, `{"model":"gemini-2.5-pro","messages":[{"role":"user","content":"hello"}]}`)
	if path != "/v1beta/openai/chat/completions" {
		t.Errorf("gemini path=%q want /v1beta/openai/chat/completions", path)
	}
}

// TestProviderKeyIsolation: each provider's key reaches ONLY its own upstream, never another.
func TestProviderKeyIsolation(t *testing.T) {
	var anthSaw, oaiSaw, gemSaw string
	anth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		anthSaw = r.Header.Get("x-api-key") + "|" + r.Header.Get("Authorization")
		_, _ = w.Write([]byte(anthroShaped))
	}))
	defer anth.Close()
	oai := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		oaiSaw = r.Header.Get("Authorization") + "|" + r.Header.Get("x-api-key")
		_, _ = w.Write([]byte(openAIShaped))
	}))
	defer oai.Close()
	gem := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gemSaw = r.Header.Get("Authorization") + "|" + r.Header.Get("x-api-key")
		_, _ = w.Write([]byte(openAIShaped))
	}))
	defer gem.Close()
	cfg := configDefaults()
	cfg.Threshold = 0
	hc := newNoRedirectClient()
	s := newServer(cfg, map[string]Backend{
		"anthropic": &anthropicBackend{key: "ANT", base: anth.URL, version: "2023-06-01", model: "claude-x", maxTokens: 4096, hc: hc},
		"openai":    oaiBackend("openai", oai.URL, "/v1/chat/completions", "OAI", hc),
		"gemini":    oaiBackend("gemini", gem.URL, "/chat/completions", "GEM", hc),
	}, hc)
	doChat(t, s, `{"model":"claude-x","messages":[{"role":"user","content":"x"}]}`)
	doChat(t, s, `{"model":"gpt-5","messages":[{"role":"user","content":"x"}]}`)
	doChat(t, s, `{"model":"gemini-2.5-pro","messages":[{"role":"user","content":"x"}]}`)
	if anthSaw != "ANT|" {
		t.Errorf("anthropic upstream saw %q want only x-api-key=ANT", anthSaw)
	}
	if oaiSaw != "Bearer OAI|" {
		t.Errorf("openai upstream saw %q want only Authorization=Bearer OAI", oaiSaw)
	}
	if gemSaw != "Bearer GEM|" {
		t.Errorf("gemini upstream saw %q want only Authorization=Bearer GEM", gemSaw)
	}
}

// TestProviderMissingKeyIsolated: a missing provider key 503s that provider only; others serve.
func TestProviderMissingKeyIsolated(t *testing.T) {
	anth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(anthroShaped))
	}))
	defer anth.Close()
	cfg := configDefaults()
	cfg.Threshold = 0
	hc := newNoRedirectClient()
	s := newServer(cfg, map[string]Backend{
		"anthropic": &anthropicBackend{key: "ANT", base: anth.URL, version: "2023-06-01", model: "claude-x", maxTokens: 4096, hc: hc},
		"openai":    oaiBackend("openai", "http://127.0.0.1:9", "/v1/chat/completions", "", hc), // no key
	}, hc)
	if rr := doChat(t, s, `{"model":"gpt-5","messages":[{"role":"user","content":"x"}]}`); rr.Code != http.StatusServiceUnavailable {
		t.Errorf("openai no-key code=%d want 503", rr.Code)
	}
	if rr := doChat(t, s, `{"model":"claude-x","messages":[{"role":"user","content":"x"}]}`); rr.Code != http.StatusOK {
		t.Errorf("anthropic code=%d want 200 (unaffected by missing openai key)", rr.Code)
	}
}

// TestNoRedirectKeyLeakOpenAI: an upstream 30x must not forward the Bearer key cross-host.
func TestNoRedirectKeyLeakOpenAI(t *testing.T) {
	var evilSawAuth int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			atomic.AddInt32(&evilSawAuth, 1)
		}
		_, _ = w.Write([]byte(openAIShaped))
	}))
	defer evil.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/v1/chat/completions", http.StatusFound)
	}))
	defer up.Close()
	cfg := configDefaults()
	cfg.Threshold = 0
	hc := newNoRedirectClient()
	s := newServer(cfg, map[string]Backend{"openai": oaiBackend("openai", up.URL, "/v1/chat/completions", "sk-LEAKME", hc)}, hc)
	doChat(t, s, `{"model":"gpt-5","messages":[{"role":"user","content":"x"}]}`)
	if n := atomic.LoadInt32(&evilSawAuth); n != 0 {
		t.Fatalf("redirect target saw the Authorization header %d times — key exfil", n)
	}
}

func TestValidateBase(t *testing.T) {
	for _, c := range []struct {
		base, host string
		insecure   bool
		ok         bool
	}{
		{"https://api.openai.com", "api.openai.com", false, true},
		{"https://generativelanguage.googleapis.com/v1beta/openai", "generativelanguage.googleapis.com", false, true},
		{"http://api.openai.com", "api.openai.com", false, false},    // not https
		{"https://evil.example.com", "api.openai.com", false, false}, // wrong host
		{"http://127.0.0.1:1234", "api.openai.com", true, true},      // insecure opt-out
	} {
		err := validateBase(c.base, c.host, c.insecure)
		if (err == nil) != c.ok {
			t.Errorf("validateBase(%q,%q,%v) err=%v want ok=%v", c.base, c.host, c.insecure, err, c.ok)
		}
	}
}
