// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeValidChain writes a freshly-signed, n-record chain to a temp file and returns its path + pubkey.
func writeValidChain(t *testing.T, n int) (string, ed25519.PublicKey) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "chain.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	a := &auditLog{f: f, path: path, priv: priv, prevHash: make([]byte, sha256.Size), domain: "collector"}
	for i := 0; i < n; i++ {
		if err := a.append(provEvent{Comm: "c", Hook: "bpf", Decision: "denied", Mode: "enforce"}); err != nil {
			t.Fatal(err)
		}
	}
	a.Close()
	return path, pub
}

func appendRaw(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

// TestVerifyChainTornTail — regression for the boot-gate audit finding: a crash/power-loss mid-append can
// leave an UNPARSEABLE final record (the in-process transactional rollback in append() only fires on a
// RETURNED Write/Sync error, not a power cut). verifyChainState must TOLERATE that single interrupted tail
// (else an unclean shutdown false-bricks the next boot), WITHOUT weakening tamper detection: a forged
// (well-formed but bad-sig) final record and a torn record MID-chain must still fail closed.
func TestVerifyChainTornTail(t *testing.T) {
	// (a) an unparseable trailing fragment at EOF is tolerated; the chain verifies through its committed tail.
	pathA, pubA := writeValidChain(t, 3)
	appendRaw(t, pathA, `{"seq":4,"ts":99,"comm":"c"`) // no closing brace, no newline — an interrupted append
	n, tip, _, _, err := verifyChainState(pathA, pubA, "collector", nil)
	if err != nil {
		t.Fatalf("(a) torn final fragment must be tolerated, got err: %v", err)
	}
	if n != 3 || tip == nil {
		t.Fatalf("(a) want n=3 with a non-nil tip (the last committed record), got n=%d tip=%v", n, tip)
	}

	// (b) a valid final record missing only its trailing newline still fully verifies.
	pathB, pubB := writeValidChain(t, 2)
	data, _ := os.ReadFile(pathB)
	if len(data) > 0 && data[len(data)-1] == '\n' {
		if err := os.WriteFile(pathB, data[:len(data)-1], 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if nB, _, _, _, errB := verifyChainState(pathB, pubB, "collector", nil); errB != nil || nB != 2 {
		t.Fatalf("(b) no-trailing-newline valid chain: n=%d err=%v, want 2, nil", nB, errB)
	}

	// (c) a torn line in the MIDDLE (a non-empty line follows it) must still FAIL CLOSED.
	pathC, pubC := writeValidChain(t, 2)
	appendRaw(t, pathC, "{garbage no brace\n") // unparseable, but NOT the last line...
	appendRaw(t, pathC, `{"seq":3,"comm":"c"}`+"\n")
	if _, _, _, _, errC := verifyChainState(pathC, pubC, "collector", nil); errC == nil {
		t.Fatal("(c) a torn record mid-chain must fail closed, not be tolerated as a tail")
	}

	// (d) a FORGED final record (well-formed JSON, wrong hash/sig) must still FAIL CLOSED — tolerance
	// covers ONLY unparseable fragments, never a parseable-but-forged tail.
	pathD, pubD := writeValidChain(t, 2)
	prevData, _ := os.ReadFile(pathD)
	tipHex := lastRecordHash(t, prevData)
	forged := auditRecord{Seq: 3, TS: 1, Comm: "c", Hook: "bpf", Decision: "denied", Mode: "enforce",
		PrevHash: tipHex, Hash: hex.EncodeToString(make([]byte, sha256.Size)), Sig: hex.EncodeToString(make([]byte, ed25519.SignatureSize))}
	fb, _ := json.Marshal(forged)
	appendRaw(t, pathD, string(fb)+"\n")
	if _, _, _, _, errD := verifyChainState(pathD, pubD, "collector", nil); errD == nil {
		t.Fatal("(d) a forged well-formed final record must fail closed")
	}
}

// lastRecordHash returns the hex Hash of the last JSON record in raw chain bytes.
func lastRecordHash(t *testing.T, raw []byte) string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	var last auditRecord
	for {
		var r auditRecord
		if err := dec.Decode(&r); err != nil {
			break
		}
		last = r
	}
	if last.Hash == "" {
		t.Fatal("no record hash found")
	}
	return last.Hash
}
