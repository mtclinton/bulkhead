// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

// Host-side unit tests for ADR-0011 one-shot E1/E3 grant: the consume arithmetic the kernel
// CAS relies on, the per-hook key isolation, the grantable-hook gate (E0 ungrantable at the
// broker boundary), and the gate substrate handling the new action kind.
package main

import (
	"bytes"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"
)

// TestGrantOnceConsumeArithmetic models try_consume_grant's kernel CAS (1->0) with
// sync/atomic: from a single grant, EXACTLY ONE of many racing consumers wins; from no grant,
// none win; the count never goes negative or exceeds 1.
func TestGrantOnceConsumeArithmetic(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		var count uint64 = 1
		var wins int64
		var wg sync.WaitGroup
		for i := 0; i < 64; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if atomic.CompareAndSwapUint64(&count, 1, 0) {
					atomic.AddInt64(&wins, 1)
				}
			}()
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("iter %d: %d consumers won, want exactly 1", iter, wins)
		}
		if count != 0 {
			t.Fatalf("iter %d: count=%d after consume, want 0", iter, count)
		}
	}
	var spent uint64 = 0
	if atomic.CompareAndSwapUint64(&spent, 1, 0) {
		t.Fatal("CAS on an already-spent (0) grant must not win")
	}
}

// TestGrantKeyPerHookDistinct: the broker<->BPF key is exactly 16 bytes and a ptrace grant,
// a setuid grant, and a different cgroup's setuid grant are all byte-distinct — so a grant
// for one (cgroup,hook) can never satisfy another. Guards the ABI against padding drift.
func TestGrantKeyPerHookDistinct(t *testing.T) {
	enc := func(cg uint64, h uint32) []byte {
		var b bytes.Buffer
		if err := binary.Write(&b, binary.LittleEndian, bpfGrantKey{Cgid: cg, Hook: h}); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	su := enc(2002, hookSetuid)
	pt := enc(2002, hookPtrace)
	su2 := enc(3003, hookSetuid)
	if len(su) != 16 {
		t.Fatalf("grantKey encodes to %d bytes, want 16", len(su))
	}
	if bytes.Equal(su, pt) {
		t.Fatal("same cgroup, setuid vs ptrace keys must differ (per-hook isolation)")
	}
	if bytes.Equal(su, su2) {
		t.Fatal("setuid keys for different cgroups must differ (cross-cgroup isolation)")
	}
}

// TestGrantHookRejectsNonGrantable: only E1/E3 hooks are grantable; E0 bpf, E2 socket_connect,
// and unknown names are refused at the broker boundary (defense in depth — the kernel never
// reads a HOOK_BPF grant anyway).
func TestGrantHookRejectsNonGrantable(t *testing.T) {
	for _, ok := range []string{"ptrace", "setuid", "capset"} {
		if _, g := grantableHook(ok); !g {
			t.Fatalf("%q must be grantable", ok)
		}
	}
	for _, no := range []string{"bpf", "socket_connect", "nope", ""} {
		if _, g := grantableHook(no); g {
			t.Fatalf("%q must NOT be grantable", no)
		}
	}
}

// TestGrantOnceGateAgnostic: the register/resolve gate delivers a verdict exactly-once for a
// pending{kind: actGrantOnce}, like the other gated actions.
func TestGrantOnceGateAgnostic(t *testing.T) {
	resetPend()
	p := &pending{kind: actGrantOnce, parentCgID: 9, grantHook: hookSetuid}
	if !register(p) {
		t.Fatal("register failed")
	}
	go resolve(p.id, true, "approve", "op")
	if ok := <-p.decision; !ok {
		t.Fatal("decision should be approve")
	}
	if p.verdict != "approve" || p.operator != "op" {
		t.Fatalf("verdict/operator = %q/%q", p.verdict, p.operator)
	}
}
