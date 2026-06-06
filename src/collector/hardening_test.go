// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"strings"
	"testing"
)

// TestDelegatedDropInRejectsControlCharRouterURL — regression for the contested security-audit finding:
// a routerURL carrying a control char (a literal newline would otherwise inject systemd directives into the
// child's drop-in) must be DROPPED, not written; a clean URL is written as a single double-quoted assignment
// (matching the adjacent task line). Defense-in-depth — the value is operator-set/TCB, but the gap is closed.
func TestDelegatedDropInRejectsControlCharRouterURL(t *testing.T) {
	evil := "http://127.0.0.1:8080\nExecStart=/usr/bin/malicious"
	got := delegatedDropIn("net-loopback", "worker", evil, false)
	if strings.Contains(got, "BULKHEAD_ROUTER_URL") || strings.Contains(got, "malicious") {
		t.Fatalf("control-char routerURL was written (injection not prevented):\n%s", got)
	}
	clean := delegatedDropIn("net-loopback", "worker", "http://127.0.0.1:8080", false)
	if !strings.Contains(clean, `Environment="BULKHEAD_ROUTER_URL=http://127.0.0.1:8080"`) {
		t.Fatalf("clean routerURL not written as a quoted assignment:\n%s", clean)
	}
}

// TestDecodeECDSASig — regression for the mustHex audit-clarity finding: a malformed-hex signature component
// is a DISTINCT, explicit error (not a silent zero that logs like a real signature mismatch); valid hex
// decodes to the right integers. The crypto stays fail-closed either way.
func TestDecodeECDSASig(t *testing.T) {
	if _, _, err := decodeECDSASig("zz", "00"); err == nil || !strings.Contains(err.Error(), "R not valid hex") {
		t.Fatalf("malformed R: want 'R not valid hex' error, got %v", err)
	}
	if _, _, err := decodeECDSASig("00", "zz"); err == nil || !strings.Contains(err.Error(), "S not valid hex") {
		t.Fatalf("malformed S: want 'S not valid hex' error, got %v", err)
	}
	r, s, err := decodeECDSASig("0a", "ff")
	if err != nil || r == nil || s == nil || r.Int64() != 10 || s.Int64() != 255 {
		t.Fatalf("valid hex: got r=%v s=%v err=%v (want 10, 255, nil)", r, s, err)
	}
}
