// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

// validateRouterChain re-runs verify-audit's core invariants over the on-disk file: per-boot-contiguous
// seq (genesis seq=1), continuous prev_hash linkage, and a recomputed+signature-verified hash — exactly
// the checks the boot gate (collector verify.go) would fail-close on. Returns the record count.
func validateRouterChain(t *testing.T, path string, pub ed25519.PublicKey, domain string) int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open chain: %v", err)
	}
	defer f.Close()
	prev := make([]byte, sha256.Size)
	var expectSeq uint64
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		ln := bytes.TrimSpace(sc.Bytes())
		if len(ln) == 0 {
			continue
		}
		var r auditRecord
		if err := json.Unmarshal(ln, &r); err != nil {
			t.Fatalf("record %d: malformed json: %v", n+1, err)
		}
		if r.Seq == 1 {
			expectSeq = 1
		} else {
			expectSeq++
		}
		if r.Seq != expectSeq {
			t.Fatalf("record %d: seq=%d, expected %d (GAP/reorder — the Write-fault brick)", n+1, r.Seq, expectSeq)
		}
		if !bytes.Equal(mustHex(t, r.PrevHash), prev) {
			t.Fatalf("record %d (seq %d): prev_hash linkage broken (FORK — the Sync-fault brick)", n+1, r.Seq)
		}
		sum := sha256.Sum256(canonical(r, prev, domain))
		if !bytes.Equal(mustHex(t, r.Hash), sum[:]) {
			t.Fatalf("record %d (seq %d): hash mismatch", n+1, r.Seq)
		}
		if !ed25519.Verify(pub, sum[:], mustHex(t, r.Sig)) {
			t.Fatalf("record %d (seq %d): signature invalid", n+1, r.Seq)
		}
		prev = sum[:]
		n++
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return n
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// newTestAudit builds an auditLog over a fault-injecting file in a temp dir with a fresh key.
func newTestAudit(t *testing.T, ff *faultFile) (*auditLog, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &auditLog{
		f:        ff,
		path:     ff.Name(),
		priv:     priv,
		prevHash: make([]byte, sha256.Size),
		domain:   "router",
	}, pub
}

// TestAppendTransactionalRollback — regression for the router-audit-chain audit finding: append() must not
// brick the verify-audit boot gate on a single transient I/O error. A Write failure must not leave a.seq
// advanced (which would gap the on-disk seq on the next append); a Sync failure after a successful Write
// must roll the durable-but-unacked record back (else the next append forks prev_hash). After the fault is
// cleared, a clean retry must produce a gap-free, fork-free, signature-valid chain.
func TestAppendTransactionalRollback(t *testing.T) {
	for _, tc := range []struct {
		name        string
		failWriteOn int
		failSyncOn  int
	}{
		{"write-fault", 2, 0}, // the 2nd record's Write errors (nothing durable) -> must not leave a seq gap
		{"sync-fault", 0, 2},  // the 2nd record's Write succeeds but Sync errors -> must truncate the unacked tail
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit-router")
			osf, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			ff := &faultFile{File: osf, failWriteOn: tc.failWriteOn, failSyncOn: tc.failSyncOn}
			a, pub := newTestAudit(t, ff)
			defer a.Close()

			if err := a.append(auditEvent{Comm: "router", Hook: "route", Decision: "local", Mode: "rec1"}); err != nil {
				t.Fatalf("record 1 should append cleanly: %v", err)
			}
			sizeAfter1, _ := osf.Stat()

			// The 2nd append hits the injected fault and MUST fail without committing the in-memory tip.
			if err := a.append(auditEvent{Comm: "router", Hook: "route", Decision: "api", Mode: "rec2-faulted"}); err == nil {
				t.Fatal("the faulted 2nd append must return an error")
			}
			if a.seq != 1 {
				t.Fatalf("a.seq advanced to %d on a faulted append — the next record will gap the chain", a.seq)
			}
			if fi, _ := osf.Stat(); fi.Size() != sizeAfter1.Size() {
				t.Fatalf("file not rolled back: size %d != post-record-1 size %d (an unacked tail strands on disk)", fi.Size(), sizeAfter1.Size())
			}

			// Fault cleared: the retry must succeed and yield a valid 2-record chain.
			ff.failWriteOn, ff.failSyncOn = 0, 0
			if err := a.append(auditEvent{Comm: "router", Hook: "route", Decision: "api", Mode: "rec2-retry"}); err != nil {
				t.Fatalf("retry after the fault cleared should append cleanly: %v", err)
			}
			if a.seq != 2 {
				t.Fatalf("a.seq = %d after a clean retry, want 2", a.seq)
			}
			if n := validateRouterChain(t, path, pub, "router"); n != 2 {
				t.Fatalf("chain has %d records, want exactly 2 (rec1 + the retried rec2)", n)
			}
		})
	}
}
