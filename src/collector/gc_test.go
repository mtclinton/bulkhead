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
	del := selectGrantPrunes(keys, live, nil) // nil grantSeen == cmdGC authoritative one-shot
	if len(del) != 1 || del[0].Cgid != 200 {
		t.Fatalf("selectGrantPrunes = %v, want exactly {200,setuid}", del)
	}
	// Recycle: a cgid present in BOTH live and as a grant key must NOT be pruned (its inode
	// currently backs a live agent dir).
	if del2 := selectGrantPrunes([]bpfGrantKey{{Cgid: 100, Hook: hookPtrace}}, live, nil); len(del2) != 0 {
		t.Fatalf("a recycled-onto-live cgid must never be pruned, got %v", del2)
	}
}

// TestSelectGrantPrunesRaceGuard — regression for BH-001 (the gc-delete/writer race). The concurrent
// gcLoop scans live cgids lock-free (gc.go:230, deliberately outside controlMu for latency) and only
// then takes controlMu to delete. A grant_once written by handleBrokerConn for an agent that was created
// AFTER that scan (so it is absent from the stale `live` set) must NOT be reaped on the racing pass.
// With a non-nil grantSeen the selector applies the same two-pass witnessed-live guard as egress: a dead
// cgid is pruned only if a PRIOR pass saw it live. A never-witnessed dead cgid (the freshly-written grant)
// is spared; once a later pass witnesses it live and it then dies, it is reaped. nil grantSeen (cmdGC's
// one-shot, not concurrent with the loop) keeps the authoritative single-pass — covered above.
func TestSelectGrantPrunesRaceGuard(t *testing.T) {
	grantSeen := map[uint64]struct{}{} // the loop's persistent witnessed-live set, fresh
	// Pass 1: cgid 200's grant exists but 200 is NOT in the (stale, race-losing) live set and was never
	// witnessed live -> it is the freshly-written-during-the-race grant and MUST be spared, not reaped.
	if del := selectGrantPrunes([]bpfGrantKey{{Cgid: 200, Hook: hookSetuid}}, map[uint64]struct{}{}, grantSeen); len(del) != 0 {
		t.Fatalf("a never-witnessed dead grant cgid was reaped (the BH-001 race): %v", del)
	}
	// Pass 2: 200 is now witnessed live -> recorded in grantSeen, still not pruned.
	if del := selectGrantPrunes([]bpfGrantKey{{Cgid: 200, Hook: hookSetuid}}, map[uint64]struct{}{200: {}}, grantSeen); len(del) != 0 {
		t.Fatalf("a live grant cgid must never be pruned, got %v", del)
	}
	if _, ok := grantSeen[200]; !ok {
		t.Fatal("a witnessed-live grant cgid (200) must be recorded in grantSeen")
	}
	// Pass 3: 200's agent has now genuinely died (gone from live) AND was previously witnessed -> reap it.
	if del := selectGrantPrunes([]bpfGrantKey{{Cgid: 200, Hook: hookSetuid}}, map[uint64]struct{}{}, grantSeen); len(del) != 1 || del[0].Cgid != 200 {
		t.Fatalf("a witnessed-then-dead grant cgid must be reaped, got %v", del)
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
