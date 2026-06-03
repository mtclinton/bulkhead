// SPDX-License-Identifier: AGPL-3.0-only
package main

// F5: an offline/boot-time verifier for the signed audit chains. The collector and broker
// SIGN every record (Ed25519 over a SHA-256 hash chain) but nothing ever VERIFIED one —
// a signed log no one checks is just a log. This recomputes the canonical encoding, the
// hash, the prev-hash linkage, and the signature for every record, and is wired into the
// boot gate so a tampered/forged persisted chain refuses the boot (bulkhead-verify-audit
// .service → the existing selftest Requires=).
//
// Per-boot subchains: each collector/broker process starts a fresh chain (seq=1,
// prev_hash=0) and O_APPENDs to the same file, so one file is a concatenation of per-boot
// subchains. That restart-reset is accepted by design (the file is append-only across
// boots; truncation of the tail is an inherent property of any local log and is mitigated
// by shipping the log off-box). The verifier therefore treats seq==1 with a zero prev_hash
// as a legitimate boot boundary and re-anchors there; any OTHER seq reset or non-zero
// first-link is tampering.

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

var zeroHash = make([]byte, sha256.Size)

// verifyChain validates every record in an audit .jsonl against pub. Returns the count of
// verified records and the first error (fail-closed at the first bad record). A missing or
// empty file is OK (nothing has been written yet) — only a PRESENT, BROKEN chain fails.
func verifyChain(path string, pub ed25519.PublicKey, domain string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil // not yet created (first boot, before any event) — nothing to verify
		}
		return 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // tolerate long Mode strings

	prev := zeroHash         // running prev-hash; chains CONTINUOUSLY across boots (F5)
	var expectSeq uint64 = 0 // expected seq WITHIN the current per-boot subchain
	n := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r auditRecord
		if err := json.Unmarshal(line, &r); err != nil {
			return n, fmt.Errorf("record %d: malformed json: %w", n+1, err)
		}
		// seq resets to 1 at a per-boot boundary; otherwise it increments. But prev_hash
		// chains CONTINUOUSLY across boots (F5) and is NOT reset here — so deleting a whole
		// middle subchain breaks the link (the next subchain's prev_hash won't match the
		// surviving prior record's hash). Genesis is the very first record (seq=1, prev=0).
		if r.Seq == 1 {
			expectSeq = 1
		} else {
			expectSeq++
		}
		if r.Seq != expectSeq {
			return n, fmt.Errorf("record %d: seq=%d, expected %d (gap, reorder, or illegal reset)", n+1, r.Seq, expectSeq)
		}
		if !hexEqual(r.PrevHash, prev) {
			return n, fmt.Errorf("record %d (seq %d): prev_hash linkage broken (record/subchain removed or reordered)", n+1, r.Seq)
		}
		sum := sha256.Sum256(canonical(r, prev, domain))
		if !hexEqual(r.Hash, sum[:]) {
			return n, fmt.Errorf("record %d (seq %d): hash mismatch (record body tampered)", n+1, r.Seq)
		}
		sig, err := hex.DecodeString(r.Sig)
		if err != nil {
			return n, fmt.Errorf("record %d (seq %d): bad signature hex: %w", n+1, r.Seq, err)
		}
		if !ed25519.Verify(pub, sum[:], sig) {
			return n, fmt.Errorf("record %d (seq %d): signature invalid (wrong key or forged record)", n+1, r.Seq)
		}
		prev = sum[:]
		n++
	}
	if err := sc.Err(); err != nil {
		return n, err
	}
	return n, nil
}

// hexEqual reports whether the hex string decodes to exactly raw.
func hexEqual(h string, raw []byte) bool {
	b, err := hex.DecodeString(h)
	return err == nil && bytes.Equal(b, raw)
}

// cmdVerifyAudit is the operator/boot-gate entry point:
//
//	bulkhead-collector verify-audit <chain.jsonl> [pubkeyhex | @pubkeyfile]
//
// Key resolution (strongest first): an explicit pubkey arg; else the sealed seed via
// CREDENTIALS_DIRECTORY/audit-seed (the on-box boot gate — bound to the TPM/persistent
// seed an attacker can't forge); else a sibling audit-pub.txt (offline convenience, trusted
// out-of-band). Exits non-zero on any broken record so a unit ExecStart fails the boot gate.
func cmdVerifyAudit(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: bulkhead-collector verify-audit <provenance.jsonl> [pubkeyhex|@pubfile]")
		os.Exit(2)
	}
	chain := args[0]
	pub, src, err := resolveAuditPub(args[1:], filepath.Dir(chain))
	if err != nil {
		log.Fatalf("verify-audit: %v", err)
	}
	domain := chainDomain(chain)
	n, err := verifyChain(chain, pub, domain)
	if err != nil {
		log.Fatalf("verify-audit: chain INVALID (%d record(s) verified, then) %v [key: %s, domain: %s]", n, err, src, domain)
	}
	fmt.Printf("verify-audit: OK — %d record(s) verified for %s [key: %s, domain: %s]\n", n, chain, src, domain)
}

// chainDomain infers the per-chain domain (F4) the verifier must use from the chain's path.
// The two on-box chains are the collector provenance (/data/bulkhead/audit) and the broker
// decision chain (/data/bulkhead/audit-broker); the domain is the VERIFIER's belief about
// which chain this is, never read from the record (so a transplant fails). Overridable for
// offline use via BULKHEAD_AUDIT_DOMAIN.
func chainDomain(chain string) string {
	if d := os.Getenv("BULKHEAD_AUDIT_DOMAIN"); d != "" {
		return d
	}
	if strings.Contains(chain, "audit-broker") {
		return "broker"
	}
	return "collector"
}

// resolveAuditPub picks the verification key. See cmdVerifyAudit for the precedence rationale.
func resolveAuditPub(rest []string, chainDir string) (ed25519.PublicKey, string, error) {
	if len(rest) >= 1 && rest[0] != "" {
		a := rest[0]
		if strings.HasPrefix(a, "@") {
			data, err := os.ReadFile(a[1:])
			if err != nil {
				return nil, "", fmt.Errorf("read pubkey file %s: %w", a[1:], err)
			}
			return decodePubHex(string(data), "file:"+a[1:])
		}
		return decodePubHex(a, "arg")
	}
	if pub, ok := sealedAuditPub(); ok {
		return pub, "sealed-seed", nil
	}
	if data, err := os.ReadFile(filepath.Join(chainDir, "audit-pub.txt")); err == nil {
		return decodePubHex(string(data), "audit-pub.txt")
	}
	return nil, "", fmt.Errorf("no verification key: pass pubkeyhex/@file, or run with the sealed audit-seed credential, or place audit-pub.txt beside the chain")
}

// sealedAuditPub derives the public key from the sealed/persistent signing seed if the
// credential is present (the strong on-box path), without ever minting an ephemeral key.
func sealedAuditPub() (ed25519.PublicKey, bool) {
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" {
		return nil, false
	}
	seed, err := os.ReadFile(filepath.Join(dir, "audit-seed"))
	if err != nil || len(seed) < ed25519.SeedSize {
		return nil, false
	}
	return ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize]).Public().(ed25519.PublicKey), true
}

func decodePubHex(s, src string) (ed25519.PublicKey, string, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, "", fmt.Errorf("bad pubkey hex (%s): %w", src, err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, "", fmt.Errorf("pubkey wrong size (%s): %d bytes, want %d", src, len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), src, nil
}
