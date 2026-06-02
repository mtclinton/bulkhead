// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

// Host-side unit tests for the approval-gate concurrency (ADR-0007) — the
// register/resolve registry must deliver a verdict EXACTLY ONCE and resolve the
// operator-decision-vs-timeout race deterministically, without a VM.
package main

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

// TestNarrowComputesMask guards ADR-0010's clamp arithmetic: narrowMask = cur &^ req can only
// CLEAR bits (monotone-decreasing, fail-safe direction), and a requested class the agent
// lacks is a no-op on that class.
func TestNarrowComputesMask(t *testing.T) {
	lp, _ := parseClasses("loopback")
	pub, _ := parseClasses("public")
	oth, _ := parseClasses("other")
	all, _ := parseClasses("loopback,linklocal,private,public,other")
	cases := []struct {
		name           string
		cur, req, want uint32
	}{
		{"clears a held bit", lp | pub, pub, lp},
		{"unheld class is a no-op on it", lp | oth, pub, lp | oth},
		{"clamp all -> none", all, all, 0},
		{"multi clear", lp | pub | oth, pub | oth, lp},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := narrowMask(c.cur, c.req)
			if got != c.want {
				t.Fatalf("narrowMask(%#x,%#x)=%#x, want %#x", c.cur, c.req, got, c.want)
			}
			if got&^c.cur != 0 {
				t.Fatalf("narrow SET a bit: %#x is not a subset of cur %#x", got, c.cur)
			}
			if got&c.req != 0 {
				t.Fatalf("narrow left a requested bit set: req %#x still in %#x", c.req, got)
			}
		})
	}
}

// TestResolveAgentTargetRejectsNonAgent guards ADR-0010's target gate: narrow may only ever
// resolve a cgroup under /bulkhead-agent.slice/bulkhead-agent@ — never the TCB, PID-1, the
// operator's own session, an id:N, a traversal, or a malformed instance.
func TestResolveAgentTargetRejectsNonAgent(t *testing.T) {
	if _, _, err := resolveAgentTarget("id:42"); !errors.Is(err, errNarrowID) {
		t.Fatalf("id:42 -> %v, want errNarrowID", err)
	}
	for _, p := range []string{
		"/system.slice/bulkhead-collector.service",
		"/sys/fs/cgroup/system.slice/bulkhead-broker.service",
		"/bulkhead-agent.slice/../system.slice/x.service", // traversal escaping the slice
	} {
		if _, _, err := resolveAgentTarget(p); !errors.Is(err, errNarrowNotAgent) {
			t.Fatalf("%q -> %v, want errNarrowNotAgent", p, err)
		}
	}
	for _, b := range []string{"../etc", "a/b", "WithCaps", "has.dot"} {
		if _, _, err := resolveAgentTarget(b); !errors.Is(err, errNarrowBadInst) {
			t.Fatalf("bad instance %q -> %v, want errNarrowBadInst", b, err)
		}
	}
	// A well-formed but nonexistent agent passes the slice predicate, then fails at the live
	// stat — proving the gate did NOT reject it (it's a real attempt that simply isn't running).
	if _, _, err := resolveAgentTarget("nonexistent-agent-xyz"); !errors.Is(err, errNarrowGone) {
		t.Fatalf("nonexistent agent -> %v, want errNarrowGone", err)
	}
}

// TestReverifyCgroupRebindsIdentity guards the F1/F3 re-binding: at execute() time the
// requester's attested cgroup id must still match the LIVE inode at its path, or the action
// fails closed (recycle onto a new agent, or a vanished cgroup). Exercised against the
// cgroup root, which always exists on a cgroup-v2 host.
func TestReverifyCgroupRebindsIdentity(t *testing.T) {
	const root = "" // filepath.Join("/sys/fs/cgroup", "") -> /sys/fs/cgroup
	live, err := cgroupIDFromInode(filepath.Join("/sys/fs/cgroup", root))
	if err != nil {
		t.Skipf("no cgroupfs on build host: %v", err)
	}
	if err := reverifyCgroup(root, live); err != nil {
		t.Fatalf("reverify of the live id must pass: %v", err)
	}
	if err := reverifyCgroup(root, live+1); err == nil {
		t.Fatal("reverify of a recycled (mismatched) id must fail closed")
	}
	if err := reverifyCgroup("/bulkhead-nonexistent.slice/nope.service", live); err == nil {
		t.Fatal("reverify of a vanished path must fail closed")
	}
}

// resetPend clears the global registry between tests.
func resetPend() {
	pendMu.Lock()
	pend = map[uint64]*pending{}
	pendPerPar = map[uint64]int{}
	pendNext = 0
	pendMu.Unlock()
}

func TestRegisterResolveExactlyOnce(t *testing.T) {
	resetPend()
	p := &pending{parentCgID: 100}
	if !register(p) {
		t.Fatal("register failed")
	}
	if got := resolve(p.id, true, "approve", "op"); !got {
		t.Fatal("first resolve should win")
	}
	if v := <-p.decision; v != true {
		t.Fatalf("decision = %v, want true", v)
	}
	if p.verdict != "approve" || p.operator != "op" {
		t.Fatalf("verdict/operator = %q/%q", p.verdict, p.operator)
	}
	// A second resolve (a late operator decision or the timeout) must be a no-op.
	if got := resolve(p.id, false, "timeout", "-"); got {
		t.Fatal("second resolve must be a no-op")
	}
	// Registry must be empty + per-parent counter decremented.
	pendMu.Lock()
	if len(pend) != 0 || pendPerPar[100] != 0 {
		t.Fatalf("registry not cleaned: pend=%d perPar=%d", len(pend), pendPerPar[100])
	}
	pendMu.Unlock()
}

// TestResolveRaceSingleDelivery: many goroutines racing allow-vs-timeout on one entry;
// exactly one wins, the decision channel receives exactly one value, no double-launch.
func TestResolveRaceSingleDelivery(t *testing.T) {
	for iter := 0; iter < 200; iter++ {
		resetPend()
		p := &pending{parentCgID: 7}
		register(p)
		var wins int32
		var wg sync.WaitGroup
		results := make(chan bool, 8)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			allow := i%2 == 0
			go func() {
				defer wg.Done()
				if resolve(p.id, allow, "v", "op") {
					results <- allow
				}
			}()
		}
		// exactly one resolve wins -> exactly one channel value
		got := <-p.decision
		wg.Wait()
		close(results)
		for range results {
			wins++
		}
		if wins != 1 {
			t.Fatalf("iter %d: %d resolvers reported winning, want 1", iter, wins)
		}
		_ = got
	}
}

func TestFloodCaps(t *testing.T) {
	resetPend()
	// per-parent cap
	for i := 0; i < maxPendingPar; i++ {
		if !register(&pending{parentCgID: 42}) {
			t.Fatalf("register %d under per-parent cap should succeed", i)
		}
	}
	if register(&pending{parentCgID: 42}) {
		t.Fatal("register past per-parent cap must be rejected")
	}
	// a different parent is unaffected (until the global cap)
	if !register(&pending{parentCgID: 43}) {
		t.Fatal("a different parent under caps should succeed")
	}
}

// TestExpandComputesMask: the widen arithmetic — add requested classes within the
// ceiling, never beyond it, never remove a held class.
func TestExpandComputesMask(t *testing.T) {
	all := dstLoopback | dstLinklocal | dstPrivate | dstPublic | dstOther
	for _, c := range []struct {
		cur, req, ceiling, want uint32
	}{
		{dstLoopback | dstOther, dstPublic, all, dstLoopback | dstOther | dstPublic}, // add public
		{dstLoopback | dstOther, dstLoopback, all, dstLoopback | dstOther},           // already held -> no change
		{dstLoopback, dstPublic, dstLoopback | dstOther, dstLoopback},                // public above ceiling -> clamped
		{dstLoopback, dstPublic | dstPrivate, dstPublic, dstLoopback | dstPublic},    // only the in-ceiling bit added
		{0, dstPublic, all, dstPublic},                                               // from empty (note: handler refuses no-manifest separately)
	} {
		if got := expandMask(c.cur, c.req, c.ceiling); got != c.want {
			t.Errorf("expandMask(0x%x,0x%x,0x%x)=0x%x want 0x%x", c.cur, c.req, c.ceiling, got, c.want)
		}
		// widening never removes a held class:
		if got := expandMask(c.cur, c.req, c.ceiling); got&c.cur != c.cur {
			t.Errorf("expandMask dropped a held class: cur=0x%x got=0x%x", c.cur, got)
		}
	}
}

// TestGateActionAgnostic: the register/resolve gate delivers a verdict exactly once for a
// NON-delegate action kind too (the gate is the reusable substrate).
func TestGateActionAgnostic(t *testing.T) {
	resetPend()
	p := &pending{kind: actExpandEgress, parentCgID: 9}
	if !register(p) {
		t.Fatal("register expand pending failed")
	}
	if !resolve(p.id, true, "approve", "op") {
		t.Fatal("first resolve should win")
	}
	if v := <-p.decision; v != true || p.verdict != "approve" {
		t.Fatalf("decision=%v verdict=%q", v, p.verdict)
	}
	if resolve(p.id, false, "deny", "op2") {
		t.Fatal("second resolve must be a no-op (exactly-once)")
	}
}
