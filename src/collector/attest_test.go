// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// composeDigestGoldenV1 pins composeDigest over exeHash=sha256("") + the default-armed posture
// {bpf=1, socket_connect=1, ptrace/setuid/capset=0} + tcb {count=3, clean}. It is the canonical
// byte format the box extends and the off-box `attest expected-d` recomputes (ADR-0022); a silent
// refactor drift (reorder, prefix, hook-set, or tag change) fails CI here rather than changing the
// digest behind the "bulkhead-attest-v1" tag. (Re-derive with: `attest expected-d /dev/null`.)
const composeDigestGoldenV1 = "4d79e5d7d2ef3d6b9b9c0df88130cdff3fe2d3767b5e92c56900807c92dcc856"

func emptyExeHex() string { s := sha256.Sum256(nil); return hex.EncodeToString(s[:]) }

func TestComposeDigestGoldenV1(t *testing.T) {
	got := composeDigest(emptyExeHex(), map[uint32]uint32{hookBPF: 1, hookConnect: 1}, expectedTCBCount, true)
	if hex.EncodeToString(got[:]) != composeDigestGoldenV1 {
		t.Fatalf("composeDigest v1 byte format drifted: got %s want %s", hex.EncodeToString(got[:]), composeDigestGoldenV1)
	}
}

// An absent hook in flagVals must serialize as 0 (observe), exactly like the live Lookup miss — so the
// off-box expected-d ({bpf,connect} only) is byte-identical to an explicit full vector. If this breaks,
// expected-d diverges from what the live box extends and every verify fails.
func TestComposeDigestAbsentHookIsObserve(t *testing.T) {
	partial := composeDigest(emptyExeHex(), map[uint32]uint32{hookBPF: 1, hookConnect: 1}, 3, true)
	full := composeDigest(emptyExeHex(), map[uint32]uint32{hookBPF: 1, hookPtrace: 0, hookConnect: 1, hookSetuid: 0, hookCapset: 0}, 3, true)
	if partial != full {
		t.Fatal("absent hook != explicit 0 (observe) — expected-d would diverge from the live digest")
	}
}

// Every input must bind: flipping any field changes D (so a tampered posture/binary cannot collide
// with the expected good digest).
func TestComposeDigestFieldsBind(t *testing.T) {
	base := composeDigest(emptyExeHex(), map[uint32]uint32{hookBPF: 1, hookConnect: 1}, 3, true)
	cases := map[string][32]byte{
		"e0 observe": composeDigest(emptyExeHex(), map[uint32]uint32{hookConnect: 1}, 3, true),
		"e2 observe": composeDigest(emptyExeHex(), map[uint32]uint32{hookBPF: 1}, 3, true),
		"tcb dirty":  composeDigest(emptyExeHex(), map[uint32]uint32{hookBPF: 1, hookConnect: 1}, 3, false),
		"tcb count":  composeDigest(emptyExeHex(), map[uint32]uint32{hookBPF: 1, hookConnect: 1}, 4, true),
		"binary":     composeDigest("00", map[uint32]uint32{hookBPF: 1, hookConnect: 1}, 3, true),
	}
	for name, d := range cases {
		if d == base {
			t.Fatalf("%s did not change D — the field is not bound into the digest", name)
		}
	}
}
