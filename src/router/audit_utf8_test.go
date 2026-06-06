// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"
)

// TestRecordRouteInvalidUTF8RoundTrip — regression for the audit-integrity DoS (security audit, CRITICAL).
// An untrusted client model name that is invalid UTF-8 must still produce a signed record that re-verifies
// AFTER the JSON round-trip — else verify-audit fails the boot gate CLOSED on a self-inconsistent record, so
// a single crafted network request bricks the appliance on its next reboot. The fix coerces the chained
// string fields to valid UTF-8 in append() before signing; here the persisted Mode must be valid UTF-8 and
// its hash/signature must verify against canonical() recomputed from the bytes on disk.
func TestRecordRouteInvalidUTF8RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provenance.jsonl")
	a := newTestAuditLog(t, path, "router")
	pub := a.priv.Public().(ed25519.PublicKey)

	// A short (<=cap, so not truncated) model carrying an incomplete UTF-8 sequence (E4 B8 with no final byte).
	if err := a.recordRoute("api", "over threshold", "claude-\xe4\xb8-experimental", 9001, "anthropic"); err != nil {
		t.Fatalf("recordRoute: %v", err)
	}
	a.Close()

	data, _ := os.ReadFile(path)
	lines := splitLines(data)
	if len(lines) != 1 {
		t.Fatalf("want 1 persisted record, got %d", len(lines))
	}
	var r auditRecord
	if err := json.Unmarshal(lines[0], &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !utf8.ValidString(r.Mode) {
		t.Fatalf("persisted Mode is not valid UTF-8: %q", r.Mode)
	}
	prev := make([]byte, sha256.Size)
	sum := sha256.Sum256(canonical(r, prev, "router"))
	if r.Hash != hex.EncodeToString(sum[:]) {
		t.Fatalf("hash mismatch after the JSON round-trip — canonical(persisted) != signed (the brick)")
	}
	sig, _ := hex.DecodeString(r.Sig)
	if !ed25519.Verify(pub, sum[:], sig) {
		t.Fatalf("signature invalid after the JSON round-trip (the brick)")
	}
}

// TestRecordRouteRuneSafeTruncation — the byte cap must truncate on a rune boundary, keeping the byte-bound
// DoS cap AND valid UTF-8 (so a multi-byte rune straddling the cap is never split mid-way).
func TestRecordRouteRuneSafeTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provenance.jsonl")
	a := newTestAuditLog(t, path, "router")

	// 199 ASCII bytes + 中 (E4 B8 AD) straddles byte 200; the rune-safe cut must drop the whole rune.
	model := ""
	for i := 0; i < 199; i++ {
		model += "a"
	}
	model += "中-trailer"
	if err := a.recordRoute("local", "below threshold", model, 5, ""); err != nil {
		t.Fatalf("recordRoute: %v", err)
	}
	a.Close()

	data, _ := os.ReadFile(path)
	var r auditRecord
	if err := json.Unmarshal(splitLines(data)[0], &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !utf8.ValidString(r.Mode) {
		t.Fatalf("truncated Mode is not valid UTF-8 (rune split mid-way): %q", r.Mode)
	}
}
