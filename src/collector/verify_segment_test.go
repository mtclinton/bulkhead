// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

// buildSegmentedChain hand-rolls a segmented chain in dir: it writes perSeg records, then "rotates" by
// renaming the live file to <base>.NNNNNN and reopening a FRESH live file WITHOUT resetting a.prevHash/
// a.seq (exactly what the signer's rotate() does — the seam is link-continuous), repeating `segs` times,
// then writes a final liveN records into the live file. Returns the live path + the verifying pubkey. This
// proves verifySegmentedChain follows a real link-continuous seam INDEPENDENT of the signer's rotate(), so
// the verifier is fielded-correct before any box produces a segment (the R8 "never meet a segment the
// verifier can't follow" discipline / ADR-0038).
func buildSegmentedChain(t *testing.T, dir string, perSeg, segs, liveN int) (string, ed25519.PublicKey) {
	t.Helper()
	const base = "provenance.jsonl"
	live := filepath.Join(dir, base)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(live, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	a := &auditLog{f: f, path: live, priv: priv, prevHash: make([]byte, sha256.Size), domain: "collector"}
	write := func(k int) {
		for i := 0; i < k; i++ {
			if err := a.append(provEvent{Comm: "c", Hook: "bpf", Decision: "denied", Mode: "enforce"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	for s := 1; s <= segs; s++ {
		write(perSeg)
		a.Close()
		if err := os.Rename(live, segmentPath(dir, base, uint64(s))); err != nil {
			t.Fatal(err)
		}
		nf, err := os.OpenFile(live, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		a.f = nf // KEEP a.prevHash/a.seq across the seam — link-continuous, NOT a per-boot reset
	}
	write(liveN)
	a.Close()
	return live, pub
}

// TestVerifySegmentedHappyPath: a 2-segment + live chain verifies as ONE continuous chain, the count is
// the sum, and the reported tip is the LIVE file's tip (what a quote binds via attestChainHeads).
func TestVerifySegmentedHappyPath(t *testing.T) {
	dir := t.TempDir()
	live, pub := buildSegmentedChain(t, dir, 3, 2, 2) // segments 000001,000002 (3 each) + 2 live = 8
	if got := listSegments(dir, "provenance.jsonl"); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("listSegments = %v, want [1 2]", got)
	}
	n, tip, _, _, err := verifySegmentedChain(live, pub, "collector", nil)
	if err != nil {
		t.Fatalf("segmented verify failed: %v", err)
	}
	if n != 8 {
		t.Fatalf("verified %d records, want 8", n)
	}
	if !bytes.Equal(tip, lastChainHash(live)) {
		t.Fatal("reported tip != live-file tip")
	}
}

// TestVerifySegmentedDeleteMiddleFailsClosed: deleting a MIDDLE sealed segment must break the prev_hash
// seam from the prior segment's tip to the next segment's first record — the same whole-subchain-deletion
// detection the single-file verifier has, now across the segment seam. (The core R9 integrity property.)
func TestVerifySegmentedDeleteMiddleFailsClosed(t *testing.T) {
	dir := t.TempDir()
	live, pub := buildSegmentedChain(t, dir, 3, 3, 1) // segments 1,2,3 + live
	if err := os.Remove(segmentPath(dir, "provenance.jsonl", 2)); err != nil {
		t.Fatal(err)
	}
	if n, _, _, _, err := verifySegmentedChain(live, pub, "collector", nil); err == nil {
		t.Fatalf("expected fail-closed after deleting middle segment 000002, got OK (%d records)", n)
	}
}

// TestVerifySegmentedEmptyLiveSeedsFromSegment reproduces the rename-then-crash window: segments present,
// the live file empty (0 records). The whole chain must verify (tip == newest segment's tip, NOT genesis),
// and lastChainTip — what the signer/attest seed from — must agree, so a quote in that window binds the
// real tip and the next append links to it (a forged zero-prev first live record would then fail closed).
func TestVerifySegmentedEmptyLiveSeedsFromSegment(t *testing.T) {
	dir := t.TempDir()
	live, pub := buildSegmentedChain(t, dir, 4, 1, 0) // 1 segment of 4, live present but empty
	if fi, _ := os.Stat(live); fi == nil || fi.Size() != 0 {
		t.Fatalf("expected an empty live file, got %v", fi)
	}
	n, tip, _, _, err := verifySegmentedChain(live, pub, "collector", nil)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if n != 4 {
		t.Fatalf("verified %d records, want 4", n)
	}
	segTip := lastChainHash(segmentPath(dir, "provenance.jsonl", 1))
	if !bytes.Equal(tip, segTip) {
		t.Fatal("tip != segment tip (the empty live file must NOT re-anchor at genesis)")
	}
	if !bytes.Equal(lastChainTip(dir, "provenance.jsonl"), segTip) {
		t.Fatal("lastChainTip != segment tip (signer/attest would seed a spurious genesis)")
	}
}

// TestVerifySegmentedNoSegmentsIsLegacy: with no sealed siblings, verifySegmentedChain must behave exactly
// like the single-file verifyChainState (the boot gate passes one live path; un-rotated boxes are common).
func TestVerifySegmentedNoSegmentsIsLegacy(t *testing.T) {
	dir := t.TempDir()
	live, pub := buildSegmentedChain(t, dir, 0, 0, 5) // never rotated: 5 records, no segments
	if got := listSegments(dir, "provenance.jsonl"); len(got) != 0 {
		t.Fatalf("listSegments = %v, want none", got)
	}
	nSeg, tipSeg, _, _, errSeg := verifySegmentedChain(live, pub, "collector", nil)
	nOne, tipOne, _, _, errOne := verifyChainState(live, pub, "collector", nil)
	if errSeg != nil || errOne != nil {
		t.Fatalf("verify errors: seg=%v one=%v", errSeg, errOne)
	}
	if nSeg != nOne || nSeg != 5 || !bytes.Equal(tipSeg, tipOne) {
		t.Fatalf("segmented(%d,%x) != single-file(%d,%x)", nSeg, tipSeg, nOne, tipOne)
	}
}

// TestVerifySegmentedTornTailOnlyLive: a torn final record is tolerated in the LIVE file (interrupted
// append) but is mid-chain corruption in a SEALED segment and must fail closed.
func TestVerifySegmentedTornTailOnlyLive(t *testing.T) {
	// (a) torn tail in the live file — tolerated.
	dirA := t.TempDir()
	liveA, pubA := buildSegmentedChain(t, dirA, 3, 1, 2)
	appendRaw(t, liveA, `{"seq":99,"ts":1,"comm":"c"`) // interrupted append, no brace/newline
	if n, _, _, _, err := verifySegmentedChain(liveA, pubA, "collector", nil); err != nil {
		t.Fatalf("torn tail in LIVE file must be tolerated, got %v (n=%d)", err, n)
	}
	// (b) torn tail in a SEALED segment — fail closed.
	dirB := t.TempDir()
	liveB, pubB := buildSegmentedChain(t, dirB, 3, 1, 2)
	appendRaw(t, segmentPath(dirB, "provenance.jsonl", 1), `{"seq":99,"ts":1,"comm":"c"`)
	if _, _, _, _, err := verifySegmentedChain(liveB, pubB, "collector", nil); err == nil {
		t.Fatal("torn tail in a SEALED segment must fail closed, got OK")
	}
}
