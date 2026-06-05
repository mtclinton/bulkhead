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

// ADR-0023 self-check derives the SAME default-armed D the off-box `attest expected-d` does — both go
// through expectedDefaultArmedD, so the on-box gate verifies against the identical expected digest a
// relying party would. If these diverge the self-check would never match a healthy box's boot extend.
func TestExpectedDefaultArmedDMatchesComposeDigest(t *testing.T) {
	got := expectedDefaultArmedD(emptyExeHex())
	want := composeDigest(emptyExeHex(), map[uint32]uint32{hookBPF: 1, hookConnect: 1}, expectedTCBCount, true)
	if got != want {
		t.Fatalf("expectedDefaultArmedD != composeDigest(default-armed): on-box self-check D would diverge from off-box expected-d")
	}
	if hex.EncodeToString(got[:]) != composeDigestGoldenV1 {
		t.Fatalf("expectedDefaultArmedD drifted from the pinned v1 golden")
	}
}

// verifyEnvelopeChecks must RETURN an error (never fatalf/exit) so the in-process self-check can
// fail-closed gracefully — and it must reject a garbage quote rather than panic. (The full positive
// path needs a real TPM quote and is covered live by scripts/qemu-attest-check.py.)
func TestVerifyEnvelopeChecksReturnsErrorOnGarbage(t *testing.T) {
	env := &attestEnvelope{Quoted: "deadbeef", PCR: attestPCR}
	if err := verifyEnvelopeChecks(env, make([]byte, 32), make([]byte, 32), nil); err == nil {
		t.Fatal("verifyEnvelopeChecks accepted a garbage envelope — it must fail closed with an error")
	}
}

// ---- ADR-0025: quoteExtraData (the no-rewind chain-HEAD binding) --------------------------------

// qedNonce/qedColl/qedCtrl/qedBroker are fixed, reproducible inputs for the golden vector.
func qedNonce() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}
func qedHead(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

// quoteExtraDataGoldenV1 pins quoteExtraData over the fixed inputs — the canonical domain-tagged,
// length-prefixed byte format the box binds into the quote and BOTH verify paths recompute. A silent
// drift (reorder, tag, prefix, or HEAD-order change) fails CI here rather than silently breaking every
// real verify. (Re-derive: run TestQuoteExtraDataGoldenV1 and read the reported value.)
const quoteExtraDataGoldenV1 = "61ea1963aa1a5225706038d86d8f426637ef87ca1310898b4b56773314076411"

func TestQuoteExtraDataGoldenV1(t *testing.T) {
	got := quoteExtraData(qedNonce(), qedHead("collector"), qedHead("control"), qedHead("broker"))
	if hex.EncodeToString(got[:]) != quoteExtraDataGoldenV1 {
		t.Fatalf("quoteExtraData v1 byte format drifted: got %s want %s", hex.EncodeToString(got[:]), quoteExtraDataGoldenV1)
	}
}

// A genesis/nil HEAD must bind IDENTICALLY to an explicit 32-zero-byte HEAD — so a fresh box (empty
// chain => lastChainHash nil) and a relying party's "0"*64 expected agree on the bound value.
func TestQuoteExtraDataGenesisIsZero(t *testing.T) {
	zeros := make([]byte, sha256.Size)
	a := quoteExtraData(qedNonce(), nil, nil, nil)
	b := quoteExtraData(qedNonce(), zeros, zeros, zeros)
	if a != b {
		t.Fatal("nil HEAD != explicit 32 zero bytes — a genesis chain would not match a '0'*64 expected HEAD")
	}
}

// Every input must bind, and the three HEAD slots must NOT alias (swapping collector<->control changes
// the digest) — so a box cannot pass off one chain's HEAD as another's, nor rewind one undetected.
func TestQuoteExtraDataFieldsBind(t *testing.T) {
	n, c, ct, b := qedNonce(), qedHead("collector"), qedHead("control"), qedHead("broker")
	base := quoteExtraData(n, c, ct, b)
	other := make([]byte, 32) // an all-zero (genesis) HEAD, distinct from each qedHead
	cases := map[string][32]byte{
		"nonce":         quoteExtraData(qedHead("other-nonce"), c, ct, b),
		"collector":     quoteExtraData(n, other, ct, b),
		"control":       quoteExtraData(n, c, other, b),
		"broker":        quoteExtraData(n, c, ct, other),
		"swap coll/ctl": quoteExtraData(n, ct, c, b),
	}
	for name, d := range cases {
		if d == base {
			t.Fatalf("%s did not change ExtraData — the field is not bound / slots alias", name)
		}
	}
}

// The binding is DOMAIN-SEPARATED: it can never equal the raw nonce (the ADR-0019 bare-nonce
// QualifyingData) nor a bare SHA-256(nonce) — so a quote bound under the old scheme can never be
// mistaken for a HEAD-bound one and vice versa.
func TestQuoteExtraDataDomainSeparated(t *testing.T) {
	n := qedNonce()
	got := quoteExtraData(n, nil, nil, nil)
	if hex.EncodeToString(got[:]) == hex.EncodeToString(n) {
		t.Fatal("ExtraData == raw nonce — would collide with an ADR-0019 bare-nonce quote")
	}
	bare := sha256.Sum256(n)
	if got == bare {
		t.Fatal("ExtraData == SHA-256(nonce) — not domain-separated")
	}
}

// parseExpectedHeads round-trips the colon-joined form `attest heads` prints, and rejects malformed
// input (wrong arity, bad hex, wrong length) — fail-closed at parse so a typo can't degrade the check.
func TestParseExpectedHeads(t *testing.T) {
	c, ct, b := qedHead("collector"), qedHead("control"), qedHead("broker")
	in := hex.EncodeToString(c) + ":" + hex.EncodeToString(ct) + ":" + hex.EncodeToString(b)
	gc, gct, gb, err := parseExpectedHeads(in)
	if err != nil {
		t.Fatalf("parseExpectedHeads rejected a valid triple: %v", err)
	}
	if hex.EncodeToString(gc) != hex.EncodeToString(c) || hex.EncodeToString(gct) != hex.EncodeToString(ct) || hex.EncodeToString(gb) != hex.EncodeToString(b) {
		t.Fatal("parseExpectedHeads round-trip mismatch")
	}
	for _, bad := range []string{
		"",                    // empty
		hex.EncodeToString(c), // 1 part
		hex.EncodeToString(c) + ":" + hex.EncodeToString(ct),         // 2 parts
		"zz:" + hex.EncodeToString(ct) + ":" + hex.EncodeToString(b), // bad hex
		"00:" + hex.EncodeToString(ct) + ":" + hex.EncodeToString(b), // wrong length (1 byte)
	} {
		if _, _, _, err := parseExpectedHeads(bad); err == nil {
			t.Fatalf("parseExpectedHeads accepted malformed input %q", bad)
		}
	}
}
