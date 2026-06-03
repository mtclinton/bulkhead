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

// newTestLog opens an auditLog on path with a deterministic key (so the test owns the pub) and
// a domain, CONTINUING the hash chain from the prior content (F5 cross-boot linkage) just like
// openAuditLog.
func newTestLog(t *testing.T, path, domain string, priv ed25519.PrivateKey) *auditLog {
	t.Helper()
	prev := make([]byte, sha256.Size)
	if h := lastChainHash(path); h != nil {
		prev = h
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return &auditLog{f: f, path: path, priv: priv, prevHash: prev, domain: domain}
}

// TestVerifyChainRoundTrip: a chain written by append() verifies, INCLUDING across a per-boot
// subchain boundary (a second process, seq resets to 1 but prev_hash CONTINUES the chain).
func TestVerifyChainRoundTrip(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	path := filepath.Join(t.TempDir(), "provenance.jsonl")

	a := newTestLog(t, path, "test", priv)
	for i := 0; i < 3; i++ {
		if err := a.append(provEvent{CgroupID: uint64(100 + i), Comm: "agent", Hook: "ptrace", Decision: "denied", Mode: "enforce"}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	a.Close()
	// Second "boot": seq resets to 1, but prev_hash links to the first boot's last hash.
	b := newTestLog(t, path, "test", priv)
	if err := b.append(provEvent{CgroupID: 200, Comm: "agent", Hook: "delegate", Decision: "approve", Mode: "op req=x applied=y"}); err != nil {
		t.Fatalf("append2: %v", err)
	}
	b.Close()

	n, err := verifyChain(path, pub, "test")
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
	if n, err := verifyChain(filepath.Join(dir, "nope.jsonl"), pub, "test"); err != nil || n != 0 {
		t.Fatalf("missing chain: got (%d,%v), want (0,nil) — nothing to verify is OK", n, err)
	}
	empty := filepath.Join(dir, "empty.jsonl")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := verifyChain(empty, pub, "test"); err != nil || n != 0 {
		t.Fatalf("empty chain: got (%d,%v), want (0,nil)", n, err)
	}
}

func TestVerifyChainDetectsTamper(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)

	write3 := func(t *testing.T) string {
		path := filepath.Join(t.TempDir(), "p.jsonl")
		a := newTestLog(t, path, "test", priv)
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
		tampered := strings.Replace(string(raw), `"decision":"denied"`, `"decision":"allowed"`, 1)
		if tampered == string(raw) {
			t.Fatal("test setup: nothing replaced")
		}
		os.WriteFile(path, []byte(tampered), 0o600)
		if _, err := verifyChain(path, pub, "test"); err == nil {
			t.Fatal("tampered record body must fail verification")
		}
	})

	t.Run("dropped middle record -> linkage breaks", func(t *testing.T) {
		path := write3(t)
		raw, _ := os.ReadFile(path)
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		kept := lines[0] + "\n" + lines[2] + "\n"
		os.WriteFile(path, []byte(kept), 0o600)
		if _, err := verifyChain(path, pub, "test"); err == nil {
			t.Fatal("dropping a record must break the chain")
		}
	})

	t.Run("wrong key -> signature invalid", func(t *testing.T) {
		path := write3(t)
		other := ed25519.NewKeyFromSeed(append(make([]byte, ed25519.SeedSize-1), 9)).Public().(ed25519.PublicKey)
		if _, err := verifyChain(path, other, "test"); err == nil {
			t.Fatal("a chain must not verify under the wrong public key")
		}
	})
}

// TestVerifyChainDetectsSubchainDeletion guards F5: deleting a whole per-boot subchain must
// break the cross-boot prev_hash linkage (re-anchoring at every seq=1/prev=0 let it pass before).
func TestVerifyChainDetectsSubchainDeletion(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	path := filepath.Join(t.TempDir(), "p.jsonl")
	for boot := 0; boot < 3; boot++ { // three per-boot subchains, each continuing the prior hash
		a := newTestLog(t, path, "test", priv)
		for i := 0; i < 2; i++ {
			if err := a.append(provEvent{CgroupID: uint64(boot*10 + i), Comm: "a", Hook: "ptrace", Decision: "denied", Mode: "enforce"}); err != nil {
				t.Fatal(err)
			}
		}
		a.Close()
	}
	if _, err := verifyChain(path, pub, "test"); err != nil {
		t.Fatalf("an intact 3-boot chain must verify: %v", err)
	}
	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 6 {
		t.Fatalf("want 6 records, got %d", len(lines))
	}
	// Delete the entire MIDDLE subchain (boot 1 = records 3,4); keep boots 0 and 2.
	kept := lines[0] + "\n" + lines[1] + "\n" + lines[4] + "\n" + lines[5] + "\n"
	os.WriteFile(path, []byte(kept), 0o600)
	if _, err := verifyChain(path, pub, "test"); err == nil {
		t.Fatal("deleting a whole middle subchain must break cross-boot linkage")
	}
}

// TestVerifyChainRejectsWrongDomain guards F4: a record signed for one chain's domain must not
// verify under another's (the cross-chain transplant the shared seed otherwise allows).
func TestVerifyChainRejectsWrongDomain(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	path := filepath.Join(t.TempDir(), "p.jsonl")
	a := newTestLog(t, path, "broker", priv)
	if err := a.append(provEvent{CgroupID: 1, Comm: "self", Hook: "grant-once", Decision: "approve", Mode: "op op=setuid applied=x"}); err != nil {
		t.Fatal(err)
	}
	a.Close()
	if _, err := verifyChain(path, pub, "broker"); err != nil {
		t.Fatalf("same-domain verification must pass: %v", err)
	}
	if _, err := verifyChain(path, pub, "collector"); err == nil {
		t.Fatal("a broker-domain record must NOT verify under the collector domain")
	}
}
