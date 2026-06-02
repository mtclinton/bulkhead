// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestLog opens an auditLog on path with a deterministic key (so the test owns the pub).
func newTestLog(t *testing.T, path string, priv ed25519.PrivateKey) *auditLog {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return &auditLog{f: f, path: path, priv: priv, prevHash: make([]byte, sha256.Size)}
}

// TestVerifyChainRoundTrip: a chain written by append() verifies, INCLUDING across a
// per-boot subchain boundary (a second process re-anchoring at seq=1/prev=0 in the same
// file). This is the happy path the boot gate depends on.
func TestVerifyChainRoundTrip(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	path := filepath.Join(t.TempDir(), "provenance.jsonl")

	a := newTestLog(t, path, priv)
	for i := 0; i < 3; i++ {
		if err := a.append(provEvent{CgroupID: uint64(100 + i), Comm: "agent", Hook: "ptrace", Decision: "denied", Mode: "enforce"}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	a.Close()
	// Second "boot": a fresh log re-anchors (seq=1, prev=0) and appends to the same file.
	b := newTestLog(t, path, priv)
	if err := b.append(provEvent{CgroupID: 200, Comm: "agent", Hook: "delegate", Decision: "approve", Mode: "op req=x applied=y"}); err != nil {
		t.Fatalf("append2: %v", err)
	}
	b.Close()

	n, err := verifyChain(path, pub)
	if err != nil {
		t.Fatalf("verifyChain on a good 2-boot chain: %v", err)
	}
	if n != 4 {
		t.Fatalf("verified %d records, want 4 (3 + 1 across a boot boundary)", n)
	}
}

func TestVerifyChainMissingAndEmpty(t *testing.T) {
	dir := t.TempDir()
	pub := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if n, err := verifyChain(filepath.Join(dir, "nope.jsonl"), pub); err != nil || n != 0 {
		t.Fatalf("missing chain: got (%d,%v), want (0,nil) — nothing to verify is OK", n, err)
	}
	empty := filepath.Join(dir, "empty.jsonl")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := verifyChain(empty, pub); err != nil || n != 0 {
		t.Fatalf("empty chain: got (%d,%v), want (0,nil)", n, err)
	}
}

func TestVerifyChainDetectsTamper(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)

	write3 := func(t *testing.T) string {
		path := filepath.Join(t.TempDir(), "p.jsonl")
		a := newTestLog(t, path, priv)
		for i := 0; i < 3; i++ {
			if err := a.append(provEvent{CgroupID: uint64(i), Comm: "agent", Hook: "socket_connect", Decision: "denied", Mode: "enforce"}); err != nil {
				t.Fatal(err)
			}
		}
		a.Close()
		return path
	}

	t.Run("body edit -> hash mismatch", func(t *testing.T) {
		path := write3(t)
		raw, _ := os.ReadFile(path)
		// Flip the recorded decision in the body without re-signing: the stored hash no
		// longer matches the recomputed canonical hash.
		tampered := strings.Replace(string(raw), `"decision":"denied"`, `"decision":"allowed"`, 1)
		if tampered == string(raw) {
			t.Fatal("test setup: nothing replaced")
		}
		os.WriteFile(path, []byte(tampered), 0o600)
		if _, err := verifyChain(path, pub); err == nil {
			t.Fatal("tampered record body must fail verification")
		}
	})

	t.Run("dropped middle record -> linkage breaks", func(t *testing.T) {
		path := write3(t)
		raw, _ := os.ReadFile(path)
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		// Remove the middle record; record 3's prev_hash no longer matches record 1's hash,
		// and its seq jumps 1 -> 3.
		kept := lines[0] + "\n" + lines[2] + "\n"
		os.WriteFile(path, []byte(kept), 0o600)
		if _, err := verifyChain(path, pub); err == nil {
			t.Fatal("dropping a record must break the chain")
		}
	})

	t.Run("wrong key -> signature invalid", func(t *testing.T) {
		path := write3(t)
		other := ed25519.NewKeyFromSeed(append(make([]byte, ed25519.SeedSize-1), 9)).Public().(ed25519.PublicKey)
		if _, err := verifyChain(path, other); err == nil {
			t.Fatal("a chain must not verify under the wrong public key")
		}
	})
}
