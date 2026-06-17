// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

// rotSeedCredDir provisions a STABLE audit seed (so openAuditLog signs with a fixed identity across
// reopens — required to verify a cross-reboot rotated chain) and returns the matching pubkey.
func rotSeedCredDir(t *testing.T) ed25519.PublicKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i*7 + 1)
	}
	cred := t.TempDir()
	if err := os.WriteFile(filepath.Join(cred, "audit-seed"), seed, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", cred)
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
}

func fileSize(t *testing.T, p string) int64 {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return fi.Size()
}

func appendRecords(t *testing.T, a *auditLog, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := a.append(provEvent{Comm: "c", Hook: "bpf", Decision: "denied", Mode: "enforce"}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
}

// TestRotationVerifiesAcrossManySegmentsNoPrune: with retention high enough that nothing is pruned, a
// chain that rotates several times verifies end to end as ONE continuous chain, oldest segment == 000001
// (genesis, strictly anchored). Proves the rotation seam is link-continuous independent of pruning.
func TestRotationVerifiesAcrossManySegmentsNoPrune(t *testing.T) {
	pub := rotSeedCredDir(t)
	adir := t.TempDir()
	t.Setenv("BULKHEAD_AUDIT_DIR", adir)
	t.Setenv("BULKHEAD_AUDIT_SEGMENT_BYTES", "1500")
	t.Setenv("BULKHEAD_AUDIT_SEGMENTS_KEEP", "100")
	a, err := openAuditLog("collector", "provenance.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	const N = 40
	appendRecords(t, a, N)
	a.Close()

	live := filepath.Join(adir, "provenance.jsonl")
	segs := listSegments(adir, "provenance.jsonl")
	if len(segs) < 2 {
		t.Fatalf("expected multiple segments (1500B threshold, %d records), got %v", N, segs)
	}
	if segs[0] != 1 {
		t.Fatalf("oldest segment must be 000001 with no prune, got %06d", segs[0])
	}
	n, _, _, _, err := verifySegmentedChain(live, pub, "collector", nil)
	if err != nil {
		t.Fatalf("segmented verify failed: %v", err)
	}
	if n != N {
		t.Fatalf("verified %d records, want %d", n, N)
	}
}

// TestRotationPruneBoundsFootprintAndVerifies is the core R9 test: with keep=1 a long run prunes the head
// (oldest segment number > 1), the on-disk footprint stays bounded at (keep+1)*bytes + slack, AND the
// chain STILL verifies via the retained-head anchor (without anchorFirst this would false-brick: the
// oldest retained segment's first record links to a pruned-and-gone predecessor).
func TestRotationPruneBoundsFootprintAndVerifies(t *testing.T) {
	pub := rotSeedCredDir(t)
	adir := t.TempDir()
	t.Setenv("BULKHEAD_AUDIT_DIR", adir)
	t.Setenv("BULKHEAD_AUDIT_SEGMENT_BYTES", "1500")
	t.Setenv("BULKHEAD_AUDIT_SEGMENTS_KEEP", "1")
	a, err := openAuditLog("collector", "provenance.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	appendRecords(t, a, 200) // many rotations -> head pruned
	a.Close()

	live := filepath.Join(adir, "provenance.jsonl")
	segs := listSegments(adir, "provenance.jsonl")
	if len(segs) != 1 {
		t.Fatalf("keep=1 must retain exactly 1 sealed segment, got %v", segs)
	}
	if segs[0] == 1 {
		t.Fatal("expected the head to be pruned (oldest segment > 000001); pruning did not fire")
	}
	foot := fileSize(t, live) + fileSize(t, segmentPath(adir, "provenance.jsonl", segs[0]))
	if cap := int64(2*1500 + 2000); foot > cap {
		t.Fatalf("footprint %d exceeds (keep+1)*bytes + slack (%d) — prune did not bound it", foot, cap)
	}
	n, tip, _, _, err := verifySegmentedChain(live, pub, "collector", nil)
	if err != nil {
		t.Fatalf("pruned chain must verify via the retained-head anchor: %v", err)
	}
	if n == 0 || tip == nil {
		t.Fatalf("expected nonzero verified records + a tip, got n=%d tip=%x", n, tip)
	}
}

// TestRotationPrunedMiddleDeletionFailsClosed: in a head-pruned chain (oldest segment > 1, so the oldest
// is relaxed-anchored), deleting a MIDDLE retained segment must STILL fail closed — the seam from the
// prior retained segment's tip to the next segment's first record breaks. This is the property the
// retained-head anchor must NOT weaken: only the very oldest retained file is relaxed.
func TestRotationPrunedMiddleDeletionFailsClosed(t *testing.T) {
	pub := rotSeedCredDir(t)
	adir := t.TempDir()
	t.Setenv("BULKHEAD_AUDIT_DIR", adir)
	t.Setenv("BULKHEAD_AUDIT_SEGMENT_BYTES", "1500")
	t.Setenv("BULKHEAD_AUDIT_SEGMENTS_KEEP", "3")
	a, err := openAuditLog("collector", "provenance.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	appendRecords(t, a, 200)
	a.Close()

	live := filepath.Join(adir, "provenance.jsonl")
	segs := listSegments(adir, "provenance.jsonl")
	if len(segs) != 3 || segs[0] == 1 {
		t.Fatalf("want 3 retained segments with the head pruned, got %v", segs)
	}
	if _, _, _, _, err := verifySegmentedChain(live, pub, "collector", nil); err != nil {
		t.Fatalf("the pruned chain must verify before tamper: %v", err)
	}
	if err := os.Remove(segmentPath(adir, "provenance.jsonl", segs[1])); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := verifySegmentedChain(live, pub, "collector", nil); err == nil {
		t.Fatal("deleting a MIDDLE retained segment in a pruned chain must fail closed")
	}
}

// TestRotationAcrossReboot: a chain that rotates, is closed (reboot), reopened (openAuditLog seeds the
// prevHash from the tip via lastChainTip), and appended-to must verify as ONE chain linking across BOTH
// the segment seams AND the reboot boundary. (The rename->reopen->append path the appliance actually runs.)
func TestRotationAcrossReboot(t *testing.T) {
	pub := rotSeedCredDir(t)
	adir := t.TempDir()
	t.Setenv("BULKHEAD_AUDIT_DIR", adir)
	t.Setenv("BULKHEAD_AUDIT_SEGMENT_BYTES", "1500")
	t.Setenv("BULKHEAD_AUDIT_SEGMENTS_KEEP", "100")
	boot := func(n int) {
		a, err := openAuditLog("collector", "provenance.jsonl")
		if err != nil {
			t.Fatal(err)
		}
		appendRecords(t, a, n)
		a.Close()
	}
	boot(20) // boot 1: several rotations
	boot(20) // boot 2: reopen + more rotations, linking across the reboot

	live := filepath.Join(adir, "provenance.jsonl")
	n, _, _, _, err := verifySegmentedChain(live, pub, "collector", nil)
	if err != nil {
		t.Fatalf("cross-reboot segmented verify failed: %v", err)
	}
	if n != 40 {
		t.Fatalf("verified %d records, want 40", n)
	}
}

// TestRotationRenameFailureContinuesAppend is the R1 invariant: a rotation that cannot complete (here the
// rename target is blocked by a pre-existing directory) must NEVER fail the append — it degrades to "keep
// writing the current file". No record is lost, and the result verifies. (A rotation glitch under attack
// volume must not become the cross-tier append DoS R9 exists to remove.)
func TestRotationRenameFailureContinuesAppend(t *testing.T) {
	pub := rotSeedCredDir(t)
	adir := t.TempDir()
	t.Setenv("BULKHEAD_AUDIT_DIR", adir)
	t.Setenv("BULKHEAD_AUDIT_SEGMENT_BYTES", "1500")
	t.Setenv("BULKHEAD_AUDIT_SEGMENTS_KEEP", "2")
	a, err := openAuditLog("collector", "provenance.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	// Block every rotation: os.Rename(live, <segment>) fails with EISDIR because a directory already
	// occupies the next segment path (segNext is not bumped on a failed rotate, so it stays blocked).
	blocked := segmentPath(adir, "provenance.jsonl", a.segNext)
	if err := os.MkdirAll(filepath.Join(blocked, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	const N = 40
	for i := 0; i < N; i++ {
		if err := a.append(provEvent{Comm: "c", Hook: "bpf", Decision: "denied", Mode: "enforce"}); err != nil {
			t.Fatalf("append %d must succeed despite the blocked rotation (R1), got: %v", i, err)
		}
	}
	a.Close()

	if got := listSegments(adir, "provenance.jsonl"); len(got) != 0 {
		t.Fatalf("the blocked rotation must not have produced a segment, got %v", got)
	}
	os.RemoveAll(blocked) // clear the blocker so only the (over-threshold) live file remains
	live := filepath.Join(adir, "provenance.jsonl")
	n, _, _, _, err := verifySegmentedChain(live, pub, "collector", nil)
	if err != nil {
		t.Fatalf("verify after the blocked rotation: %v", err)
	}
	if n != N {
		t.Fatalf("verified %d records, want %d (no record lost to the failed rotation)", n, N)
	}
}

// TestRotationDisabledByDefault: with no BULKHEAD_AUDIT_SEGMENT_BYTES set, rotation is OFF (rotateBytes==0)
// and the chain stays a single file — the pre-R9 behaviour preserved for dev/Buildroot.
func TestRotationDisabledByDefault(t *testing.T) {
	rotSeedCredDir(t)
	adir := t.TempDir()
	t.Setenv("BULKHEAD_AUDIT_DIR", adir)
	a, err := openAuditLog("collector", "provenance.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if a.rotateBytes != 0 {
		t.Fatalf("rotation must default to disabled, got rotateBytes=%d", a.rotateBytes)
	}
	appendRecords(t, a, 50)
	a.Close()
	if got := listSegments(adir, "provenance.jsonl"); len(got) != 0 {
		t.Fatalf("no rotation expected with the knob unset, got segments %v", got)
	}
}
