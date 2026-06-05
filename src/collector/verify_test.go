// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// canonicalRouterGoldenV1 pins the COLLECTOR's canonical() over the SAME fixed record + "router" domain as
// the router module's TestCanonicalGoldenV1 (src/router/audit_test.go). The router carries a COPY of
// canonical(); the collector's verify-audit recomputes it over router records, so the two MUST agree —
// this golden fails in CI if EITHER module's canonical() drifts (ADR-0027 cross-module drift guard).
const canonicalRouterGoldenV1 = "835f49b5abe034b3b4252fa8d2a671fb0a43ab3d3c0dfdf2d9df1249fcc36e31"

func TestCanonicalRouterDomainGolden(t *testing.T) {
	r := auditRecord{Seq: 1, TS: 0, CgroupID: 0, PID: 0, Comm: "router", Hook: "route", Decision: "local", Mode: "reason=x model=m promptlen=5"}
	prev := make([]byte, sha256.Size)
	sum := sha256.Sum256(canonical(r, prev, "router"))
	if hex.EncodeToString(sum[:]) != canonicalRouterGoldenV1 {
		t.Fatalf("collector canonical() drifted from the router's pinned golden: got %s want %s (cross-module verify would break)", hex.EncodeToString(sum[:]), canonicalRouterGoldenV1)
	}
}

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

// ADR-0026: verifyChainState returns the tip (binds to a quote's reported HEAD) and resolves no-rewind
// ancestry — a prior-observed HEAD that is a real record's VERIFIED hash is found (with its seq); a HEAD
// not in the chain (rewound/forked away) is not. This is the no-rewind verdict primitive.
func TestVerifyChainStateTipAndAncestry(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	path := filepath.Join(t.TempDir(), "provenance.jsonl")

	a := newTestLog(t, path, "test", priv)
	if err := a.append(provEvent{CgroupID: 1, Comm: "x", Hook: "ptrace", Decision: "denied", Mode: "enforce"}); err != nil {
		t.Fatalf("append1: %v", err)
	}
	mid := string(lastChainHash(path)) // the seq-1 record's hash — a prior observation
	for i := 0; i < 2; i++ {
		if err := a.append(provEvent{CgroupID: uint64(2 + i), Comm: "x", Hook: "connect", Decision: "allowed", Mode: "enforce"}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	a.Close()
	wantTip := string(lastChainHash(path))

	// nil since: tip is the last record's hash; no ancestry tracked.
	n, tip, _, found, err := verifyChainState(path, pub, "test", nil)
	if err != nil || n != 3 {
		t.Fatalf("verifyChainState: n=%d err=%v (want 3, nil)", n, err)
	}
	if string(tip) != wantTip {
		t.Fatalf("tip mismatch: got %x want %x", tip, wantTip)
	}
	if found {
		t.Fatal("foundSince true for a nil since")
	}

	// a prior observation that IS a real record's verified hash -> found, with its seq.
	if _, _, seq, found, err := verifyChainState(path, pub, "test", []byte(mid)); err != nil || !found || seq != 1 {
		t.Fatalf("ancestry of a real mid HEAD: found=%v seq=%d err=%v (want true,1,nil)", found, seq, err)
	}

	// a HEAD not in the chain (rewound/forked away) -> not found (no false-positive ancestry).
	bogus := sha256.Sum256([]byte("not in the chain"))
	if _, _, _, found, _ := verifyChainState(path, pub, "test", bogus[:]); found {
		t.Fatal("ancestry false positive: a HEAD not in the chain reported as found")
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

// TestControlChainDomain (ADR-0017): a control-socket authority record verifies under the new
// "control" domain and NOT under collector/broker (F4 transplant protection extends to the new
// chain), and chainDomain() maps the control.jsonl filename to "control" so the boot gate and
// verify-audit pick the right domain.
func TestControlChainDomain(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	path := filepath.Join(t.TempDir(), "control.jsonl")
	a := newTestLog(t, path, "control", priv)
	if err := a.append(provEvent{CgroupID: 42, Comm: "broker", Hook: "control:tcb-register-broker", Decision: "ok", Mode: "registered"}); err != nil {
		t.Fatal(err)
	}
	if err := a.append(provEvent{CgroupID: 100, Hook: "control:egress-set", Decision: "ok", Mode: "loopback,other"}); err != nil {
		t.Fatal(err)
	}
	a.Close()
	if _, err := verifyChain(path, pub, "control"); err != nil {
		t.Fatalf("a control-domain chain must verify under the control domain: %v", err)
	}
	for _, d := range []string{"collector", "broker"} {
		if _, err := verifyChain(path, pub, d); err == nil {
			t.Fatalf("a control-domain record must NOT verify under %q (transplant)", d)
		}
	}
	for path, want := range map[string]string{
		"/data/bulkhead/audit/control.jsonl":           "control",
		"/data/bulkhead/audit/provenance.jsonl":        "collector",
		"/data/bulkhead/audit-broker/provenance.jsonl": "broker",
	} {
		if got := chainDomain(path); got != want {
			t.Fatalf("chainDomain(%q)=%q want %q", path, got, want)
		}
	}
}
