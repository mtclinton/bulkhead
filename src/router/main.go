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
	ClaudeModel        string
	AnthropicBase      string
	AnthropicVersion   string
	AnthropicMaxTokens int
	AllowInsecureBase  bool
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

func configFromEnv() config {
	return config{
		Listen:             env("BULKHEAD_LISTEN", "127.0.0.1:8080"),
		LlamaURL:           strings.TrimRight(env("BULKHEAD_LLAMA_URL", "http://127.0.0.1:8081"), "/"),
		Threshold:          envInt("BULKHEAD_THRESHOLD", 2000),
		DefaultRoute:       RouteLocal,
		ClaudeModel:        env("BULKHEAD_CLAUDE_MODEL", "claude-sonnet-4-6"),
		AnthropicBase:      strings.TrimRight(env("BULKHEAD_ANTHROPIC_BASE", "https://api.anthropic.com"), "/"),
		AnthropicVersion:   env("ANTHROPIC_VERSION", "2023-06-01"),
		AnthropicMaxTokens: envInt("BULKHEAD_MAX_TOKENS_CAP", 4096),
		AllowInsecureBase:  os.Getenv("BULKHEAD_ALLOW_INSECURE_ANTHROPIC_BASE") == "1",
	}
}

// validateAnthropicBase refuses to send the key anywhere but Anthropic over TLS,
// unless an explicit opt-out is set (for testing or a pinned local proxy).
func validateAnthropicBase(base string, allowInsecure bool) error {
	u, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("invalid BULKHEAD_ANTHROPIC_BASE %q: %w", base, err)
	}
	if allowInsecure {
		return nil
	}
	if u.Scheme != "https" {
		return fmt.Errorf("BULKHEAD_ANTHROPIC_BASE must be https (got %q); set BULKHEAD_ALLOW_INSECURE_ANTHROPIC_BASE=1 to override", base)
	}
	if u.Hostname() != "api.anthropic.com" {
		return fmt.Errorf("BULKHEAD_ANTHROPIC_BASE host must be api.anthropic.com (got %q); set BULKHEAD_ALLOW_INSECURE_ANTHROPIC_BASE=1 to override", u.Hostname())
	}
	return nil
}

// loadAnthropicKey reads the key from the systemd credential directory first,
// then from an explicit file path. It deliberately never reads a key *value*
// from the environment, keeping the secret out of the process environment block.
func loadAnthropicKey() (string, error) {
	var paths []string
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		paths = append(paths, filepath.Join(dir, "anthropic-api-key"))
	}
	if f := os.Getenv("ANTHROPIC_API_KEY_FILE"); f != "" {
		paths = append(paths, f)
	}
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			if k := strings.TrimSpace(string(b)); k != "" {
				return k, nil
			}
		}
	}
	return "", errors.New("no Anthropic API key (set CREDENTIALS_DIRECTORY or ANTHROPIC_API_KEY_FILE)")
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	cfg := configFromEnv()

	if err := validateAnthropicBase(cfg.AnthropicBase, cfg.AllowInsecureBase); err != nil {
		log.Fatalf("config: %v", err)
	}

	key, err := loadAnthropicKey()
	if err != nil {
		log.Printf("warning: %v; 'api' routes will error until a key is present", err)
	}

	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           newServer(cfg, key).routes(),
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
