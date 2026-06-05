// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// canonicalGoldenV1 pins sha256(canonical(a fixed record, genesis prev, "router")) — the exact bytes the
// router signs and the collector's verify-audit recomputes. It MUST equal the IDENTICAL golden in
// src/collector (TestCanonicalRouterDomainGolden): the two modules carry COPIES of canonical(), and any
// drift between them silently breaks cross-module verification — this pins it so CI fails first.
const canonicalGoldenV1 = "835f49b5abe034b3b4252fa8d2a671fb0a43ab3d3c0dfdf2d9df1249fcc36e31"

func goldenRecord() auditRecord {
	return auditRecord{Seq: 1, TS: 0, CgroupID: 0, PID: 0, Comm: "router", Hook: "route", Decision: "local", Mode: "reason=x model=m promptlen=5"}
}

func TestCanonicalGoldenV1(t *testing.T) {
	prev := make([]byte, sha256.Size)
	sum := sha256.Sum256(canonical(goldenRecord(), prev, "router"))
	if hex.EncodeToString(sum[:]) != canonicalGoldenV1 {
		t.Fatalf("router canonical() drifted: got %s want %s", hex.EncodeToString(sum[:]), canonicalGoldenV1)
	}
}

// newTestAuditLog opens a router auditLog on path with a deterministic key (so the test owns the pub).
func newTestAuditLog(t *testing.T, path, domain string) *auditLog {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
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

// TestAppendRoundTrip: recordRoute writes well-formed, signed, hash-linked records the same shape the
// collector's verify-audit checks (seq monotonic, prev_hash linkage, hash == sha256(canonical), sig valid).
func TestAppendRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provenance.jsonl")
	a := newTestAuditLog(t, path, "router")
	pub := a.priv.Public().(ed25519.PublicKey)
	if err := a.recordRoute("local", "below threshold", "llama", 5, ""); err != nil {
		t.Fatalf("recordRoute1: %v", err)
	}
	if err := a.recordRoute("api", "over threshold", "claude-x", 9001, "anthropic"); err != nil {
		t.Fatalf("recordRoute2: %v", err)
	}
	a.Close()

	data, _ := os.ReadFile(path)
	var prev []byte = make([]byte, sha256.Size)
	var n uint64
	for _, ln := range splitLines(data) {
		var r auditRecord
		if err := json.Unmarshal(ln, &r); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		n++
		if r.Seq != n {
			t.Fatalf("seq=%d want %d", r.Seq, n)
		}
		if r.PrevHash != hex.EncodeToString(prev) {
			t.Fatalf("record %d: prev_hash linkage broken", n)
		}
		sum := sha256.Sum256(canonical(r, prev, "router"))
		if r.Hash != hex.EncodeToString(sum[:]) {
			t.Fatalf("record %d: hash mismatch", n)
		}
		sig, _ := hex.DecodeString(r.Sig)
		if !ed25519.Verify(pub, sum[:], sig) {
			t.Fatalf("record %d: signature invalid", n)
		}
		prev = sum[:]
	}
	if n != 2 {
		t.Fatalf("verified %d records, want 2", n)
	}
}

// TestConcurrentAppend: the router's HTTP handlers are concurrent, so append() must serialize under the
// mutex — run -race to prove no data race, and assert the resulting chain is well-formed (seq 1..N
// contiguous, prev_hash linked), which a torn interleave would corrupt.
func TestConcurrentAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provenance.jsonl")
	a := newTestAuditLog(t, path, "router")
	const N = 50
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := a.recordRoute("local", "r", "m", i, ""); err != nil {
				t.Errorf("append: %v", err)
			}
		}(i)
	}
	wg.Wait()
	a.Close()

	data, _ := os.ReadFile(path)
	prev := make([]byte, sha256.Size)
	seqs := map[uint64]bool{}
	var n uint64
	for _, ln := range splitLines(data) {
		var r auditRecord
		if err := json.Unmarshal(ln, &r); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		n++
		if r.PrevHash != hex.EncodeToString(prev) {
			t.Fatalf("record %d: prev_hash linkage broken (a concurrent append raced the mutex)", n)
		}
		sum := sha256.Sum256(canonical(r, prev, "router"))
		if r.Hash != hex.EncodeToString(sum[:]) {
			t.Fatalf("record %d: hash mismatch", n)
		}
		seqs[r.Seq] = true
		prev = sum[:]
	}
	if n != N {
		t.Fatalf("wrote %d records, want %d", n, N)
	}
	for s := uint64(1); s <= N; s++ {
		if !seqs[s] {
			t.Fatalf("seq %d missing — append was not serialized", s)
		}
	}
}

// TestRecordRouteCapsModel: the UNTRUSTED model string is capped in the signed record so a network-facing
// flood of oversized-model requests cannot grow the chain unboundedly (the adversarial-review DoS fix).
func TestRecordRouteCapsModel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provenance.jsonl")
	a := newTestAuditLog(t, path, "router")
	huge := strings.Repeat("A", 1<<20) // 1 MiB untrusted model
	if err := a.recordRoute("api", "r", huge, 5, "anthropic"); err != nil {
		t.Fatalf("recordRoute: %v", err)
	}
	a.Close()
	data, _ := os.ReadFile(path)
	if len(data) > 4096 {
		t.Fatalf("audit record is %d bytes — the untrusted model field was not capped (DoS vector open)", len(data))
	}
	var r auditRecord
	if err := json.Unmarshal(bytesSplitNonEmpty(data)[0], &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !strings.Contains(r.Mode, "...(truncated)") {
		t.Fatalf("capped model not marked truncated: %q", r.Mode)
	}
}

func splitLines(data []byte) [][]byte {
	var out [][]byte
	for _, ln := range bytesSplitNonEmpty(data) {
		out = append(out, ln)
	}
	return out
}

func bytesSplitNonEmpty(data []byte) [][]byte {
	var out [][]byte
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			if i > start {
				out = append(out, data[start:i])
			}
			start = i + 1
		}
	}
	if start < len(data) {
		out = append(out, data[start:])
	}
	return out
}
