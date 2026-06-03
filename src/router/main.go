// SPDX-License-Identifier: AGPL-3.0-only
//
// bulkhead-router routes each chat request to either the local llama.cpp server
// or the Anthropic API per a simple rule, while speaking the OpenAI
// chat-completions API to its clients. The Anthropic key is read only from a
// file (a systemd credential), never from an environment value, so it never
// appears in /proc/<pid>/environ.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// BuildCommit is the git commit the binary was built from, injected at build
// time via -ldflags "-X main.BuildCommit=<sha>". It anchors the AGPL section 13
// source offer to the exact running build.
var BuildCommit = "dev"

const sourceRepo = "https://github.com/mtclinton/bulkhead"

func sourceURL() string {
	if BuildCommit == "" || BuildCommit == "dev" {
		return sourceRepo
	}
	return sourceRepo + "/tree/" + BuildCommit
}

type config struct {
	Listen             string
	LlamaURL           string
	Threshold          int
	DefaultRoute       Route
	APIProvider        string // default paid provider when the model matches no prefix
	ClaudeModel        string
	AnthropicBase      string
	AnthropicVersion   string
	AnthropicMaxTokens int
	AllowInsecureBase  bool
	// OpenAI + Gemini (OpenAI-compatible) providers. Model "" => pass the client model
	// through. Per-provider insecure-base opt-outs are for httptest only.
	OpenAIBase          string
	OpenAIModel         string
	OpenAIMaxTokens     int
	AllowInsecureOpenAI bool
	GeminiBase          string
	GeminiModel         string
	GeminiMaxTokens     int
	AllowInsecureGemini bool
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// thresholdFloor guards the denial-of-wallet gate (composed-review nit): a zero/negative
// BULKHEAD_THRESHOLD would make promptLen() >= threshold ALWAYS true, routing every request —
// even an empty one — to the paid tier. Clamp to a sane minimum so the gate can't be
// misconfigured open.
func thresholdFloor(n int) int {
	const min = 64
	if n < min {
		return min
	}
	return n
}

func configFromEnv() config {
	return config{
		Listen:              env("BULKHEAD_LISTEN", "127.0.0.1:8080"),
		LlamaURL:            strings.TrimRight(env("BULKHEAD_LLAMA_URL", "http://127.0.0.1:8081"), "/"),
		Threshold:           thresholdFloor(envInt("BULKHEAD_THRESHOLD", 2000)),
		DefaultRoute:        RouteLocal,
		APIProvider:         env("BULKHEAD_API_PROVIDER", "anthropic"),
		ClaudeModel:         env("BULKHEAD_CLAUDE_MODEL", "claude-sonnet-4-6"),
		AnthropicBase:       strings.TrimRight(env("BULKHEAD_ANTHROPIC_BASE", "https://api.anthropic.com"), "/"),
		AnthropicVersion:    env("ANTHROPIC_VERSION", "2023-06-01"),
		AnthropicMaxTokens:  envInt("BULKHEAD_MAX_TOKENS_CAP", 4096),
		AllowInsecureBase:   os.Getenv("BULKHEAD_ALLOW_INSECURE_ANTHROPIC_BASE") == "1",
		OpenAIBase:          strings.TrimRight(env("BULKHEAD_OPENAI_BASE", "https://api.openai.com"), "/"),
		OpenAIModel:         env("BULKHEAD_OPENAI_MODEL", ""),
		OpenAIMaxTokens:     envInt("BULKHEAD_OPENAI_MAX_TOKENS_CAP", envInt("BULKHEAD_MAX_TOKENS_CAP", 4096)),
		AllowInsecureOpenAI: os.Getenv("BULKHEAD_ALLOW_INSECURE_OPENAI_BASE") == "1",
		GeminiBase:          strings.TrimRight(env("BULKHEAD_GEMINI_BASE", "https://generativelanguage.googleapis.com/v1beta/openai"), "/"),
		GeminiModel:         env("BULKHEAD_GEMINI_MODEL", ""),
		GeminiMaxTokens:     envInt("BULKHEAD_GEMINI_MAX_TOKENS_CAP", envInt("BULKHEAD_MAX_TOKENS_CAP", 4096)),
		AllowInsecureGemini: os.Getenv("BULKHEAD_ALLOW_INSECURE_GEMINI_BASE") == "1",
	}
}

// validateBase refuses to send a key anywhere but allowedHost over TLS, unless an
// explicit opt-out is set (for httptest or a pinned local proxy). Each provider pins its
// own host so one provider's key can never be sent to another's endpoint.
func validateBase(base, allowedHost string, allowInsecure bool) error {
	u, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("invalid base %q: %w", base, err)
	}
	if allowInsecure {
		return nil
	}
	if u.Scheme != "https" {
		return fmt.Errorf("base must be https (got %q)", base)
	}
	if u.Hostname() != allowedHost {
		return fmt.Errorf("base host must be %s (got %q)", allowedHost, u.Hostname())
	}
	return nil
}

// validateAnthropicBase is the Anthropic-pinned wrapper (kept for the existing test).
func validateAnthropicBase(base string, allowInsecure bool) error {
	return validateBase(base, "api.anthropic.com", allowInsecure)
}

// loadKeyFile reads a key from the systemd credential directory first, then from an
// explicit file path. It deliberately NEVER reads a key *value* from the environment,
// keeping the secret out of the process environment block (/proc/<pid>/environ).
func loadKeyFile(credName, fileEnv string) (string, error) {
	var paths []string
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		paths = append(paths, filepath.Join(dir, credName))
	}
	if f := os.Getenv(fileEnv); f != "" {
		paths = append(paths, f)
	}
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			if k := strings.TrimSpace(string(b)); k != "" {
				return k, nil
			}
		}
	}
	return "", fmt.Errorf("no key (set CREDENTIALS_DIRECTORY/%s or %s)", credName, fileEnv)
}

// loadAnthropicKey is the Anthropic-pinned wrapper (kept for the existing test).
func loadAnthropicKey() (string, error) {
	k, err := loadKeyFile("anthropic-api-key", "ANTHROPIC_API_KEY_FILE")
	if err != nil {
		return "", errors.New("no Anthropic API key (set CREDENTIALS_DIRECTORY or ANTHROPIC_API_KEY_FILE)")
	}
	return k, nil
}

// buildProviders constructs the paid 'api' backends (ADR-0002). Each provider's base is
// validated — a configured-but-invalid base is FATAL, never a silent fallback — and its
// key is loaded from a file (a missing key is only a warning; that provider 503s while
// the others keep serving). All share the single no-redirect client.
func buildProviders(cfg config, hc *http.Client) map[string]Backend {
	if err := validateBase(cfg.AnthropicBase, "api.anthropic.com", cfg.AllowInsecureBase); err != nil {
		log.Fatalf("anthropic base: %v", err)
	}
	if err := validateBase(cfg.OpenAIBase, "api.openai.com", cfg.AllowInsecureOpenAI); err != nil {
		log.Fatalf("openai base: %v", err)
	}
	if err := validateBase(cfg.GeminiBase, "generativelanguage.googleapis.com", cfg.AllowInsecureGemini); err != nil {
		log.Fatalf("gemini base: %v", err)
	}
	anthKey, err := loadKeyFile("anthropic-api-key", "ANTHROPIC_API_KEY_FILE")
	if err != nil {
		log.Printf("warning: anthropic: %v; claude* api routes 503 until a key is present", err)
	}
	oaiKey, err := loadKeyFile("openai-api-key", "OPENAI_API_KEY_FILE")
	if err != nil {
		log.Printf("warning: openai: %v; gpt*/o* api routes 503 until a key is present", err)
	}
	gemKey, err := loadKeyFile("gemini-api-key", "GEMINI_API_KEY_FILE")
	if err != nil {
		log.Printf("warning: gemini: %v; gemini* api routes 503 until a key is present", err)
	}
	return map[string]Backend{
		"anthropic": &anthropicBackend{key: anthKey, base: cfg.AnthropicBase, version: cfg.AnthropicVersion, model: cfg.ClaudeModel, maxTokens: cfg.AnthropicMaxTokens, hc: hc},
		"openai":    &openAICompatBackend{name: "openai", base: cfg.OpenAIBase, chatPath: "/v1/chat/completions", key: oaiKey, model: cfg.OpenAIModel, maxTokens: cfg.OpenAIMaxTokens, hc: hc},
		"gemini":    &openAICompatBackend{name: "gemini", base: cfg.GeminiBase, chatPath: "/chat/completions", key: gemKey, model: cfg.GeminiModel, maxTokens: cfg.GeminiMaxTokens, hc: hc},
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	cfg := configFromEnv()

	hc := newNoRedirectClient()
	providers := buildProviders(cfg, hc)

	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           newServer(cfg, providers, hc).routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      150 * time.Second, // must exceed the upstream client timeout
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Printf("bulkhead-router listening on %s (build %s)", cfg.Listen, BuildCommit)
		if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = hs.Shutdown(ctx)
}
