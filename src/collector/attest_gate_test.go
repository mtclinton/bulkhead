// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package main

import "testing"

// TestPosturePass — regression for the attestation audit finding: the on-box map-read posture gate must
// enforce the SAME count==expectedTCBCount(=3) invariant the off-box verifier (expectedDefaultArmedD) and
// the crypto self-check enforce. The pre-fix gate (e0 && e2 && clean) passed a broker-absent box at count=2
// (clean against a broker-dropped `expected` set) while the digest comparison rejected it — a gate-vs-verify
// divergence. posturePass must fail closed on count<3, a dirty TCB, or either hook in observe.
func TestPosturePass(t *testing.T) {
	cases := []struct {
		name          string
		e0, e2, clean bool
		count         int
		want          bool
	}{
		{"healthy armed (3 members, clean)", true, true, true, expectedTCBCount, true},
		{"broker absent (count=2, the divergence bug)", true, true, true, 2, false},
		{"count too high", true, true, true, expectedTCBCount + 1, false},
		{"dirty TCB", true, true, false, expectedTCBCount, false},
		{"E0 in observe", false, true, true, expectedTCBCount, false},
		{"E2 in observe", true, false, true, expectedTCBCount, false},
		{"all observe / empty", false, false, false, 0, false},
	}
	for _, c := range cases {
		if got := posturePass(c.e0, c.e2, c.clean, c.count); got != c.want {
			t.Errorf("%s: posturePass(e0=%t,e2=%t,clean=%t,count=%d) = %t, want %t",
				c.name, c.e0, c.e2, c.clean, c.count, got, c.want)
		}
	}
}
