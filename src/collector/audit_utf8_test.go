// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

// TestVerifyChainSurvivesInvalidUTF8 — regression for the audit-integrity DoS (security audit, CRITICAL).
// A chained string field carrying INVALID UTF-8 (a non-UTF-8 process Comm, or any untrusted field) must not
// make the persisted record fail re-verification. append() signs the bytes; json.Marshal coerces invalid
// UTF-8 to U+FFFD on write; verify-audit recomputes canonical() over the READ-BACK bytes. Without the UTF-8
// coercion in append() the signed bytes and the read-back bytes differ, so the boot gate fails CLOSED on a
// self-inconsistent record (a remote brick). FAILS without the fix; PASSES with it.
func TestVerifyChainSurvivesInvalidUTF8(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	path := filepath.Join(t.TempDir(), "provenance.jsonl")

	a := newTestLog(t, path, "test", priv)
	// Invalid UTF-8: a truncated 3-byte rune in Comm (中 = E4 B8 AD, cut short) + a lone continuation byte in Mode.
	if err := a.append(provEvent{CgroupID: 1, Comm: "agent\xe4\xb8", Hook: "route", Decision: "local", Mode: "model=cl\x80aude"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	a.Close()

	if n, err := verifyChain(path, pub, "test"); err != nil || n != 1 {
		t.Fatalf("verifyChain on an invalid-UTF-8 record: n=%d err=%v (want 1, nil)", n, err)
	}
}

// TestConcurrentAppend — regression for the broker decision-chain race (security audit, HIGH). brokerAL.append
// is invoked from concurrent connection-handler goroutines (recordDecision/recordNarrow). Without the auditLog
// mutex, a.seq++ and a.prevHash interleave and break the hash chain. Run under -race.
func TestConcurrentAppend(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	path := filepath.Join(t.TempDir(), "provenance.jsonl")

	a := newTestLog(t, path, "broker", priv)
	const n = 64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = a.append(provEvent{CgroupID: uint64(i), Comm: "agent", Hook: "delegate", Decision: "approve", Mode: "x"})
		}(i)
	}
	wg.Wait()
	a.Close()

	got, err := verifyChain(path, pub, "broker")
	if err != nil {
		t.Fatalf("verifyChain after %d concurrent appends: %v", n, err)
	}
	if got != n {
		t.Fatalf("verified %d records, want %d (a lost/duplicated seq or broken prev-link => race)", got, n)
	}
}

// TestNarrowRejectsSubCgroup — regression: operator-narrow target validation must use the anchored
// isAgentCgroup predicate, NOT a substring match, so a crafted nested path under an agent leaf does not
// resolve (the ADR-0016 C1 gap, historically missed in narrow.go).
func TestNarrowRejectsSubCgroup(t *testing.T) {
	bad := "/sys/fs/cgroup/bulkhead.slice/bulkhead-agent.slice/bulkhead-agent@worker.service/payload.scope"
	if _, _, err := resolveAgentTarget(bad); !errors.Is(err, errNarrowNotAgent) {
		t.Fatalf("sub-cgroup path resolved (want errNarrowNotAgent): err=%v", err)
	}
}
