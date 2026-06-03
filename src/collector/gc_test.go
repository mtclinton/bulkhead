// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

// Host-side unit tests for ADR-0012 TCB-context GC: the prune predicates (the safety-critical
// selection — never prune a live/recycled cgid, never prune a non-agent egress entry), the
// live-agent-cgid glob, and the interval parse. The map I/O + delete in runGCPass needs real
// BPF privileges and is exercised live in qemu; the pure selectors carry the safety logic.
package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSelectGrantPrunes(t *testing.T) {
	live := map[uint64]struct{}{100: {}}
	keys := []bpfGrantKey{
		{Cgid: 100, Hook: hookPtrace}, // live -> kept
		{Cgid: 100, Hook: hookSetuid}, // live -> kept (per-hook, both survive)
		{Cgid: 200, Hook: hookSetuid}, // dead -> pruned
	}
	del := selectGrantPrunes(keys, live)
	if len(del) != 1 || del[0].Cgid != 200 {
		t.Fatalf("selectGrantPrunes = %v, want exactly {200,setuid}", del)
	}
	// Recycle: a cgid present in BOTH live and as a grant key must NOT be pruned (its inode
	// currently backs a live agent dir).
	if del2 := selectGrantPrunes([]bpfGrantKey{{Cgid: 100, Hook: hookPtrace}}, live); len(del2) != 0 {
		t.Fatalf("a recycled-onto-live cgid must never be pruned, got %v", del2)
	}
}

func TestSelectEgressPrunes(t *testing.T) {
	live := map[uint64]struct{}{300: {}} // agentCg2 is live this pass
	seen := map[uint64]struct{}{100: {}} // agentCg was witnessed live in a prior pass
	cgids := []uint64{100, 200, 300}     // 100 dead+seen(agent); 200 dead+unseen(non-agent); 300 live
	del := selectEgressPrunes(cgids, live, seen)
	if len(del) != 1 || del[0] != 100 {
		t.Fatalf("selectEgressPrunes = %v, want exactly [100] (dead seen-agent only)", del)
	}
	if _, ok := seen[300]; !ok {
		t.Fatal("a live agent egress cgid (300) must be added to seen")
	}
	if _, ok := seen[200]; ok {
		t.Fatal("a non-agent egress cgid (200) must NEVER enter seen, so it can never be pruned")
	}
}

func TestLiveAgentCgidsGlob(t *testing.T) {
	slice := filepath.Join(t.TempDir(), "bulkhead.slice", "bulkhead-agent.slice")
	for _, inst := range []string{"a", "b"} {
		if err := os.MkdirAll(filepath.Join(slice, "bulkhead-agent@"+inst+".service"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	saved := agentSliceGlobs
	agentSliceGlobs = []string{filepath.Join(slice, "bulkhead-agent@*.service")}
	defer func() { agentSliceGlobs = saved }()

	inoA, err := cgroupIDFromInode(filepath.Join(slice, "bulkhead-agent@a.service"))
	if err != nil {
		t.Fatal(err)
	}
	inoB, _ := cgroupIDFromInode(filepath.Join(slice, "bulkhead-agent@b.service"))

	live := liveAgentCgids()
	if len(live) != 2 {
		t.Fatalf("live set size %d, want 2", len(live))
	}
	if _, ok := live[inoA]; !ok {
		t.Fatal("agent a inode missing from live set")
	}
	// A removed agent dir is skipped (treated dead — the safe direction).
	os.RemoveAll(filepath.Join(slice, "bulkhead-agent@b.service"))
	live2 := liveAgentCgids()
	if _, ok := live2[inoB]; ok {
		t.Fatal("a removed agent must be absent from the live set")
	}
	if _, ok := live2[inoA]; !ok {
		t.Fatal("the surviving agent must remain in the live set")
	}
}

func TestParseGCInterval(t *testing.T) {
	if got := parseGCInterval("30"); got != 30*time.Second {
		t.Fatalf("\"30\" -> %v, want 30s", got)
	}
	for _, bad := range []string{"0", "-5", "garbage", ""} {
		if got := parseGCInterval(bad); got != 60*time.Second {
			t.Fatalf("%q -> %v, want the 60s default", bad, got)
		}
	}
}
