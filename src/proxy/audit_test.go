//go:build linux

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// canonicalGoldenV1 pins sha256(canonical(a fixed record, genesis prev, "router")) — the SAME golden
// the router and collector pin. The proxy carries a COPY of canonical(); any drift silently breaks the
// collector's cross-module verify-audit of the egress chain, so this fails CI first.
const canonicalGoldenV1 = "835f49b5abe034b3b4252fa8d2a671fb0a43ab3d3c0dfdf2d9df1249fcc36e31"

func goldenRecord() auditRecord {
	return auditRecord{Seq: 1, TS: 0, CgroupID: 0, PID: 0, Comm: "router", Hook: "route", Decision: "local", Mode: "reason=x model=m promptlen=5"}
}

func TestCanonicalGoldenV1(t *testing.T) {
	prev := make([]byte, sha256.Size)
	sum := sha256.Sum256(canonical(goldenRecord(), prev, "router"))
	if hex.EncodeToString(sum[:]) != canonicalGoldenV1 {
		t.Fatalf("proxy canonical() drifted from the collector/router: got %s want %s", hex.EncodeToString(sum[:]), canonicalGoldenV1)
	}
}

func newTestAuditLog(t *testing.T, path string) *auditLog {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)) // deterministic; the test owns the pub
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	return &auditLog{f: f, path: path, priv: priv, prevHash: make([]byte, sha256.Size), domain: "egress-proxy"}
}

// An egress chain the proxy writes must satisfy exactly what the collector's verify-audit recomputes
// for domain "egress-proxy": seq monotonic, prev_hash linkage, hash == sha256(canonical), sig valid.
func TestEgressChainAppendVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provenance.jsonl")
	a := newTestAuditLog(t, path)
	if err := a.recordEgress("api.anthropic.com", "443", "allow", ""); err != nil {
		t.Fatal(err)
	}
	if err := a.recordEgress("10.255.255.1", "80", "deny", "allowlist"); err != nil {
		t.Fatal(err)
	}
	a.Close()

	pub := a.priv.Public().(ed25519.PublicKey)
	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 records, got %d", len(lines))
	}
	prev := make([]byte, sha256.Size)
	for n, ln := range lines {
		var r auditRecord
		if err := json.Unmarshal([]byte(ln), &r); err != nil {
			t.Fatalf("record %d: %v", n, err)
		}
		if r.Seq != uint64(n+1) {
			t.Fatalf("record %d: seq=%d want %d", n, r.Seq, n+1)
		}
		if r.PrevHash != hex.EncodeToString(prev) {
			t.Fatalf("record %d: prev_hash linkage broken", n)
		}
		sum := sha256.Sum256(canonical(r, prev, "egress-proxy"))
		if r.Hash != hex.EncodeToString(sum[:]) {
			t.Fatalf("record %d: hash mismatch", n)
		}
		sig, _ := hex.DecodeString(r.Sig)
		if !ed25519.Verify(pub, sum[:], sig) {
			t.Fatalf("record %d: signature invalid", n)
		}
		prev = sum[:]
	}
	var r0 auditRecord
	json.Unmarshal([]byte(lines[0]), &r0)
	if r0.Comm != "egress-proxy" || r0.Hook != "connect" || r0.Decision != "allow" || !strings.Contains(r0.Mode, "dst=api.anthropic.com:443") {
		t.Fatalf("unexpected record 0: %+v", r0)
	}
}
