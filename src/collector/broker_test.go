// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

// Host-side unit tests for the approval-gate concurrency (ADR-0007) — the
// register/resolve registry must deliver a verdict EXACTLY ONCE and resolve the
// operator-decision-vs-timeout race deterministically, without a VM.
package main

import (
	"sync"
	"testing"
)

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
