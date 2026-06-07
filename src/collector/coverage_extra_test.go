// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

// Host-side unit tests backfilling security-relevant collector logic that previously ran ONLY live in
// qemu: the egress-class mask<->names round-trip, the grant_once TTL stamp, and the control-chain audit
// record field mapping (the tamper-evidence content). Pure / kernel-free.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestClassNamesRoundTrip — classNames is the inverse of the (tested) parseClasses; a mask must render
// to names that parse back to the SAME mask, so `egress set`'s display can never disagree with what the
// BPF map enforces. Covers the empty (none), single, and all-bits cases.
func TestClassNamesRoundTrip(t *testing.T) {
	if got := classNames(0); got != "none" {
		t.Fatalf("classNames(0) = %q, want \"none\"", got)
	}
	all := dstLoopback | dstLinklocal | dstPrivate | dstPublic | dstOther
	cases := []uint32{
		dstLoopback, dstPublic, dstOther,
		dstLoopback | dstOther,
		dstPrivate | dstPublic,
		all,
	}
	for _, mask := range cases {
		names := classNames(mask)
		back, err := parseClasses(names)
		if err != nil {
			t.Fatalf("parseClasses(classNames(%#x)=%q) errored: %v", mask, names, err)
		}
		if back != mask {
			t.Fatalf("round-trip mismatch: mask %#x -> %q -> %#x", mask, names, back)
		}
	}
	// "none" parses back to the empty mask.
	if back, err := parseClasses(classNames(0)); err != nil || back != 0 {
		t.Fatalf("none round-trip: got (%#x, %v), want (0, nil)", back, err)
	}
}

// TestGrantExpiry — the grant_once TTL stamp (the E0-robust backstop, ADR-0011) must be a future
// CLOCK_MONOTONIC instant ~grantTTL ahead of now, and monotonicNs must not go backwards.
func TestGrantExpiry(t *testing.T) {
	a := monotonicNs()
	b := monotonicNs()
	if a == 0 || b == 0 {
		t.Fatal("monotonicNs returned 0 (CLOCK_MONOTONIC should be readable in the test env)")
	}
	if b < a {
		t.Fatalf("monotonicNs went backwards: %d then %d", a, b)
	}
	now := monotonicNs()
	exp := grantExpiry()
	if exp <= now {
		t.Fatalf("grantExpiry %d not in the future relative to now %d", exp, now)
	}
	// exp == (slightly-later-now) + grantTTL, so exp-now is grantTTL within a small scheduling slack.
	delta := int64(exp - now)
	ttl := grantTTL.Nanoseconds()
	if delta < ttl-int64(2e9) || delta > ttl+int64(2e9) {
		t.Fatalf("grantExpiry-now = %dns, want ~grantTTL (%dns) within 2s", delta, ttl)
	}
}

// TestRecordControl — the control-chain audit record (ADR-0017) must map the verb/decision/detail/cgid
// onto the chained fields, and truncate Comm to 16 bytes (the chain's fixed comm width). A nil chain is
// a safe no-op (never panics).
func TestRecordControl(t *testing.T) {
	saved := controlAL
	defer func() { controlAL = saved }()

	controlAL = nil
	recordControl("control:egress-set", "c", "ok", "loopback", 1) // must not panic

	path := filepath.Join(t.TempDir(), "control.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	controlAL = &auditLog{f: f, path: path, priv: priv, prevHash: make([]byte, sha256.Size), domain: "control"}
	recordControl("control:egress-set", strings.Repeat("x", 20), "ok", "loopback", 4242)
	controlAL.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var r auditRecord
	if err := json.Unmarshal(bytes.TrimSpace(data), &r); err != nil {
		t.Fatalf("control record not well-formed: %v", err)
	}
	if r.Hook != "control:egress-set" || r.Decision != "ok" || r.Mode != "loopback" || r.CgroupID != 4242 {
		t.Fatalf("field mapping wrong: hook=%q decision=%q mode=%q cgid=%d", r.Hook, r.Decision, r.Mode, r.CgroupID)
	}
	if r.Comm != strings.Repeat("x", 16) {
		t.Fatalf("Comm not truncated to 16: %q (len %d)", r.Comm, len(r.Comm))
	}
}
