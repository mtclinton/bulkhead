// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package main

import (
	"strings"
	"testing"
)

// TestParseVerifyArgs — regression for the boot-gate audit finding: a present-but-EMPTY --since= /
// --expect-tip= must FAIL CLOSED, not silently skip the requested no-rewind/tip check. Covers the
// offline relying-party footgun (an unset $TIP shell var expanding to `--since=`) alongside the
// pre-existing unknown-flag and extra-positional fail-closed guards, and confirms valid forms still parse.
func TestParseVerifyArgs(t *testing.T) {
	// Fail-closed cases: each must return an error (cmdVerifyAudit log.Fatalf's it).
	bad := []struct {
		name string
		args []string
		want string
	}{
		{"empty --since", []string{"--since="}, "--since= has an empty value"},
		{"whitespace --since", []string{"--since=   "}, "--since= has an empty value"},
		{"empty --expect-tip", []string{"--expect-tip="}, "--expect-tip= has an empty value"},
		{"unknown flag", []string{"--sinc=abc"}, "unknown flag"},
		{"two positionals", []string{"pubA", "pubB"}, "extra argument"},
	}
	for _, tc := range bad {
		_, _, _, err := parseVerifyArgs(tc.args)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: parseVerifyArgs(%q) err = %v, want one containing %q", tc.name, tc.args, err, tc.want)
		}
	}

	// Valid forms still parse cleanly.
	if s, _, _, err := parseVerifyArgs([]string{"--since=0000"}); err != nil || s != "0000" {
		t.Fatalf("--since=0000: got (%q, %v), want (\"0000\", nil)", s, err)
	}
	if s, _, _, err := parseVerifyArgs([]string{"--since=@/path/head"}); err != nil || s != "@/path/head" {
		t.Fatalf("--since=@file: got (%q, %v)", s, err)
	}
	if _, tip, _, err := parseVerifyArgs([]string{"--expect-tip=ABcd"}); err != nil || tip != "abcd" {
		t.Fatalf("--expect-tip lowercased: got (%q, %v), want (\"abcd\", nil)", tip, err)
	}
	if _, _, rest, err := parseVerifyArgs([]string{"pubkeyhex"}); err != nil || len(rest) != 1 || rest[0] != "pubkeyhex" {
		t.Fatalf("pubkey positional: got (%v, %v)", rest, err)
	}
	if s, tip, rest, err := parseVerifyArgs(nil); err != nil || s != "" || tip != "" || rest != nil {
		t.Fatalf("no args: got (%q, %q, %v, %v), want all-empty", s, tip, rest, err)
	}
}
