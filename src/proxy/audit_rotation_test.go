// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSegmentPathGolden pins the segment NAMING contract (ADR-0038). The collector's verifier enumerates
// the proxy's segments by this exact "%s.%06d" pattern; any drift here silently makes verify-audit miss
// or misread the egress segments, so this fails CI first (mirrors the canonical() golden discipline).
func TestSegmentPathGolden(t *testing.T) {
	cases := map[uint64]string{1: "/d/provenance.jsonl.000001", 42: "/d/provenance.jsonl.000042", 999999: "/d/provenance.jsonl.999999"}
	for n, want := range cases {
		if got := segmentPath("/d", "provenance.jsonl", n); got != want {
			t.Fatalf("segmentPath(%d) = %q, want %q (naming contract drift)", n, got, want)
		}
	}
}

func rotAppendN(t *testing.T, a *auditLog, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := a.append(auditEvent{Comm: "egress-proxy", Hook: "connect", Decision: "allow", Mode: "dst=example.com:443"}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
}

func rotStatSize(p string) int64 {
	fi, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// TestRotationBoundsFootprint: with keep=1, a long run prunes the head and the on-disk footprint stays
// bounded at (keep+1)*bytes + slack — the egress tier (the R9 DoS source) physically cannot fill /data.
func TestRotationBoundsFootprint(t *testing.T) {
	adir := t.TempDir()
	t.Setenv("BULKHEAD_AUDIT_DIR", adir)
	t.Setenv("BULKHEAD_AUDIT_SEGMENT_BYTES", "1500")
	t.Setenv("BULKHEAD_AUDIT_SEGMENTS_KEEP", "1")
	a, err := openAuditLog("egress-proxy", "provenance.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	rotAppendN(t, a, 200)
	a.Close()

	segs := listSegments(adir, "provenance.jsonl")
	if len(segs) != 1 {
		t.Fatalf("keep=1 must retain exactly 1 sealed segment, got %v", segs)
	}
	if segs[0] == 1 {
		t.Fatal("expected the head to be pruned (oldest segment > 000001)")
	}
	live := filepath.Join(adir, "provenance.jsonl")
	foot := rotStatSize(live) + rotStatSize(segmentPath(adir, "provenance.jsonl", segs[0]))
	if cap := int64(2*1500 + 2000); foot > cap {
		t.Fatalf("footprint %d exceeds (keep+1)*bytes + slack (%d)", foot, cap)
	}
}

// TestRotationDisabledByDefault: no knob => single file, pre-R9 behaviour.
func TestRotationDisabledByDefault(t *testing.T) {
	adir := t.TempDir()
	t.Setenv("BULKHEAD_AUDIT_DIR", adir)
	a, err := openAuditLog("egress-proxy", "provenance.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if a.rotateBytes != 0 {
		t.Fatalf("rotation must default off, got rotateBytes=%d", a.rotateBytes)
	}
	rotAppendN(t, a, 30)
	a.Close()
	if got := listSegments(adir, "provenance.jsonl"); len(got) != 0 {
		t.Fatalf("no rotation expected with the knob unset, got %v", got)
	}
}

// TestRotationRenameFailureContinuesAppend is the R1 invariant for the egress chain: a blocked rotation
// must never fail an append (else a rotation glitch becomes the cross-tier denial R9 removes).
func TestRotationRenameFailureContinuesAppend(t *testing.T) {
	adir := t.TempDir()
	t.Setenv("BULKHEAD_AUDIT_DIR", adir)
	t.Setenv("BULKHEAD_AUDIT_SEGMENT_BYTES", "1500")
	a, err := openAuditLog("egress-proxy", "provenance.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	blocked := segmentPath(adir, "provenance.jsonl", a.segNext)
	if err := os.MkdirAll(filepath.Join(blocked, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		if err := a.append(auditEvent{Comm: "egress-proxy", Hook: "connect", Decision: "allow", Mode: "dst=x:443"}); err != nil {
			t.Fatalf("append %d must survive a blocked rotation (R1): %v", i, err)
		}
	}
	a.Close()
	if got := listSegments(adir, "provenance.jsonl"); len(got) != 0 {
		t.Fatalf("the blocked rotation must not have produced a segment, got %v", got)
	}
}
