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
	n, _, _, _, err := verifyChainState(path, pub, domain, nil)
	return n, err
}

// verifyChainState is verifyChain plus the ADR-0026 no-rewind inputs: it additionally returns the TIP
// (the last record's hash; nil for an empty/absent chain) and — when `since` is a non-nil 32-byte HEAD —
// whether a record with that exact VERIFIED hash appears in the chain, and at what seq (foundSince/
// sinceSeq). The tip binds the verified log to a quote's reported HEAD (ADR-0025); foundSince is the
// no-rewind primitive: because verifyChain proves the records form ONE continuous linear chain, a record
// whose verified hash == a prior-observed HEAD means the verified tip DESCENDS from that observation
// (its whole prefix is byte-identical via the hash chain), so the chain extends — never rewinds or forks
// at or below — the prior observation. A fork/truncation that drops the observation cannot reproduce its
// hash and is detected (foundSince=false). The ancestry test uses the cryptographically VERIFIED `sum`,
// not the record's self-reported Hash. (seq is per-boot and resets across boots, so it is NOT used for
// the verdict — only reported for diagnostics; the hash chain is the cross-boot-safe ordering.)
func verifyChainState(path string, pub ed25519.PublicKey, domain string, since []byte) (n int, tip []byte, sinceSeq uint64, foundSince bool, err error) {
	f, e := os.Open(path)
	if e != nil {
		if os.IsNotExist(e) {
			return 0, nil, 0, false, nil // not yet created (first boot, before any event) — nothing to verify
		}
		return 0, nil, 0, false, e
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // tolerate long Mode strings

	prev := zeroHash         // running prev-hash; chains CONTINUOUSLY across boots (F5)
	var expectSeq uint64 = 0 // expected seq WITHIN the current per-boot subchain
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r auditRecord
		if e := json.Unmarshal(line, &r); e != nil {
			return n, nil, 0, false, fmt.Errorf("record %d: malformed json: %w", n+1, e)
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
			return n, nil, 0, false, fmt.Errorf("record %d: seq=%d, expected %d (gap, reorder, or illegal reset)", n+1, r.Seq, expectSeq)
		}
		if !hexEqual(r.PrevHash, prev) {
			return n, nil, 0, false, fmt.Errorf("record %d (seq %d): prev_hash linkage broken (record/subchain removed or reordered)", n+1, r.Seq)
		}
		sum := sha256.Sum256(canonical(r, prev, domain))
		if !hexEqual(r.Hash, sum[:]) {
			return n, nil, 0, false, fmt.Errorf("record %d (seq %d): hash mismatch (record body tampered)", n+1, r.Seq)
		}
		sig, e := hex.DecodeString(r.Sig)
		if e != nil {
			return n, nil, 0, false, fmt.Errorf("record %d (seq %d): bad signature hex: %w", n+1, r.Seq, e)
		}
		if !ed25519.Verify(pub, sum[:], sig) {
			return n, nil, 0, false, fmt.Errorf("record %d (seq %d): signature invalid (wrong key or forged record)", n+1, r.Seq)
		}
		if since != nil && !foundSince && bytes.Equal(sum[:], since) {
			foundSince, sinceSeq = true, r.Seq
		}
		prev = sum[:]
		n++
	}
	if e := sc.Err(); e != nil {
		return n, nil, 0, false, e
	}
	if n == 0 {
		return 0, nil, 0, false, nil
	}
	return n, prev, sinceSeq, foundSince, nil
}

// hexEqual reports whether the hex string decodes to exactly raw.
func hexEqual(h string, raw []byte) bool {
	b, err := hex.DecodeString(h)
	return err == nil && bytes.Equal(b, raw)
}

// cmdVerifyAudit is the operator/boot-gate entry point AND the ADR-0026 no-rewind verdict:
//
//	bulkhead-collector verify-audit <chain.jsonl> [pubkeyhex | @pubkeyfile] \
//	    [--since=<prior-head-hex|@file>] [--expect-tip=<quote-bound-head-hex>]
//
// Key resolution (strongest first): an explicit pubkey arg; else the sealed seed via
// CREDENTIALS_DIRECTORY/audit-seed (the on-box boot gate — bound to the TPM/persistent
// seed an attacker can't forge); else a sibling audit-pub.txt (offline convenience, trusted
// out-of-band). Exits non-zero on any broken record so a unit ExecStart fails the boot gate.
//
// ADR-0026 closes the no-rewind loop ADR-0025 deferred. After the integrity check this can render a
// single rewind/fork verdict for a relying party: --expect-tip binds the verified log to a quote's
// reported HEAD (so this IS the attested log); --since=<prior observation> proves the verified tip
// DESCENDS from a HEAD the relying party recorded earlier (no rewind/fork at or below it). Either check
// failing exits non-zero (fail-closed). With neither flag the behavior is unchanged (the boot gate).
func cmdVerifyAudit(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: bulkhead-collector verify-audit <provenance.jsonl> [pubkeyhex|@pubfile] [--since=<head-hex|@file>] [--expect-tip=<head-hex>]")
		os.Exit(2)
	}
	chain := args[0]
	var sinceArg, expectTip string
	var rest []string
	for _, a := range args[1:] {
		switch {
		case strings.HasPrefix(a, "--since="):
			sinceArg = strings.TrimPrefix(a, "--since=")
		case strings.HasPrefix(a, "--expect-tip="):
			expectTip = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(a, "--expect-tip=")))
		case strings.HasPrefix(a, "-"):
			// A misspelled flag (e.g. --sinc=) must NOT be silently dropped into rest[] and ignored —
			// that would skip a REQUESTED no-rewind/tip check yet exit 0 (false assurance). Fail closed.
			log.Fatalf("verify-audit: unknown flag %q (expected --since=<head-hex|@file> or --expect-tip=<head-hex>)", a)
		default:
			rest = append(rest, a) // the optional pubkey positional
		}
	}
	// At most ONE positional after the chain (the pubkey). Extra positionals are a typo/misuse, not a
	// silently-ignored second key — fail closed so a requested check can't be quietly skipped.
	if len(rest) > 1 {
		log.Fatalf("verify-audit: unexpected extra argument(s) %v (only one pubkey positional is accepted)", rest[1:])
	}
	pub, src, err := resolveAuditPub(rest, filepath.Dir(chain))
	if err != nil {
		log.Fatalf("verify-audit: %v", err)
	}
	domain := chainDomain(chain)

	// --since: the relying party's prior-observed HEAD (or @file). The all-zero / absent form is genesis,
	// an ancestor of any chain (vacuously CLEAN). A non-genesis value must appear as a verified record.
	var since []byte
	checkRewind := sinceArg != ""
	if checkRewind {
		s := sinceArg
		if strings.HasPrefix(s, "@") {
			data, e := os.ReadFile(s[1:])
			if e != nil {
				log.Fatalf("verify-audit: read --since file: %v", e)
			}
			s = string(data)
		}
		since, err = hex.DecodeString(strings.TrimSpace(s))
		if err != nil || len(since) != sha256.Size {
			log.Fatalf("verify-audit: --since must be a 64-hex chain HEAD (32 bytes)")
		}
	}

	n, tip, sinceSeq, foundSince, err := verifyChainState(chain, pub, domain, since)
	if err != nil {
		log.Fatalf("verify-audit: chain INVALID (%d record(s) verified, then) %v [key: %s, domain: %s]", n, err, src, domain)
	}
	tipHex := hex.EncodeToString(headOrZero(tip)) // nil (empty chain) -> 64 zeros, matching the quote's genesis
	fmt.Printf("verify-audit: OK — %d record(s) verified for %s [key: %s, domain: %s], tip=%s\n", n, chain, src, domain, tipHex)

	failed := false
	// --expect-tip: the verified tip must equal the HEAD the quote bound (ADR-0025), so this verified log
	// is provably the one the quote attested — joining the quote's non-repudiable HEAD to this continuity
	// proof. The relying party gets it from `attest verify` (the env's reported, now-attested HEAD).
	if expectTip != "" {
		if tipHex == expectTip {
			fmt.Printf("verify-audit: tip == the quote-bound HEAD (the verified log IS the one the quote attested)\n")
		} else {
			fmt.Printf("verify-audit: FAIL — tip %s != the quote-bound HEAD %s (this log is not the attested one, or it was rewound)\n", tipHex, expectTip)
			failed = true
		}
	}
	// --since: the no-rewind/no-fork verdict relative to the prior observation.
	if checkRewind {
		switch {
		case bytes.Equal(since, zeroHash):
			fmt.Printf("verify-audit: no-rewind CLEAN — prior observation is genesis (an ancestor of any chain)\n")
		case foundSince:
			fmt.Printf("verify-audit: no-rewind CLEAN — the prior-observed HEAD is a verified ancestor (seq %d) of the tip; the chain extends it (no rewind/fork at or below the observation)\n", sinceSeq)
		default:
			fmt.Printf("verify-audit: FAIL — REWOUND/FORKED: the prior-observed HEAD is NOT in the verified chain (history at or below the observation was rewound or forked)\n")
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
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
	switch {
	case strings.Contains(chain, "audit-broker"):
		return "broker"
	case strings.Contains(filepath.Base(chain), "control"): // ADR-0017: the control-write chain
		return "control"
	default:
		return "collector"
	}
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
