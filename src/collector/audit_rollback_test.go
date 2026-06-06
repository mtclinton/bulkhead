// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// faultFile wraps a real *os.File and injects a Write or Sync error on a chosen call number, delegating
// Truncate/Stat/Close to the real file — so a test can drive append()'s transactional rollback against a
// real on-disk chain. Embeds *os.File so it satisfies durableFile by overriding only Write/Sync.
type faultFile struct {
	*os.File
	failWriteOn, failSyncOn int // 1-based call number to fail; 0 = never
	writes, syncs           int
}

func (ff *faultFile) Write(p []byte) (int, error) {
	ff.writes++
	if ff.writes == ff.failWriteOn {
		return 0, fmt.Errorf("injected write fault on call %d", ff.writes)
	}
	return ff.File.Write(p)
}

func (ff *faultFile) Sync() error {
	ff.syncs++
	if ff.syncs == ff.failSyncOn {
		return fmt.Errorf("injected sync fault on call %d", ff.syncs)
	}
	return ff.File.Sync()
}

// TestAppendTransactionalRollback — regression for the audit finding (mirror of the router fix). The
// collector's append() must not brick the verify-audit boot gate on a single transient I/O error: a Write
// failure must not leave a.seq advanced (a seq gap on the next append); a Sync failure after a successful
// Write must truncate the durable-but-unacked record (else the next append forks prev_hash). After the
// fault clears, the real verifyChainState must accept the retried chain as gap-free and fork-free.
func TestAppendTransactionalRollback(t *testing.T) {
	for _, tc := range []struct {
		name        string
		failWriteOn int
		failSyncOn  int
	}{
		{"write-fault", 2, 0},
		{"sync-fault", 0, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "provenance.jsonl")
			osf, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			ff := &faultFile{File: osf, failWriteOn: tc.failWriteOn, failSyncOn: tc.failSyncOn}
			pub, priv, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			a := &auditLog{f: ff, path: path, priv: priv, prevHash: make([]byte, sha256.Size), domain: "collector"}
			defer a.Close()

			if err := a.append(provEvent{Comm: "c", Hook: "bpf", Decision: "denied", Mode: "enforce"}); err != nil {
				t.Fatalf("record 1 should append cleanly: %v", err)
			}
			sizeAfter1, _ := osf.Stat()

			if err := a.append(provEvent{Comm: "c", Hook: "setuid", Decision: "denied", Mode: "enforce"}); err == nil {
				t.Fatal("the faulted 2nd append must return an error")
			}
			if a.seq != 1 {
				t.Fatalf("a.seq advanced to %d on a faulted append — the next record will gap the chain", a.seq)
			}
			if fi, _ := osf.Stat(); fi.Size() != sizeAfter1.Size() {
				t.Fatalf("file not rolled back: size %d != post-record-1 size %d", fi.Size(), sizeAfter1.Size())
			}

			ff.failWriteOn, ff.failSyncOn = 0, 0
			if err := a.append(provEvent{Comm: "c", Hook: "setuid", Decision: "denied", Mode: "enforce"}); err != nil {
				t.Fatalf("retry after the fault cleared should append cleanly: %v", err)
			}

			// Gold standard: the real boot-gate verifier must accept the retried chain.
			n, _, _, _, err := verifyChainState(path, pub, "collector", nil)
			if err != nil {
				t.Fatalf("verifyChainState rejected the post-fault chain (the brick): %v", err)
			}
			if n != 2 {
				t.Fatalf("verifyChainState found %d records, want exactly 2", n)
			}
		})
	}
}
