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
//
// DETECTION BOUNDARY (deliberate, ADR-0030). What this on-box verifier DETECTS fail-closed:
// any in-place edit, fork, reorder, illegal seq reset, forged signature, or deletion of an
// INTERIOR record / whole MIDDLE subchain (the continuous cross-boot prev_hash linkage breaks).
// What it deliberately does NOT detect on-box: (a) deletion of the WHOLE chain file, or
// truncation of its LATEST tail — byte-indistinguishable from a legitimate first boot / empty
// chain to any purely-local verifier (a box cannot non-circularly verify its own deletable
// history against its own deletable anchor); and (b) an UNPARSEABLE final record from an
// interrupted append (crash/power-loss after the write, before the in-process rollback) is
// TOLERATED as a partial tail (verifyChainState), required so an unclean shutdown does not
// false-brick the boot. Both (a) and (b) are the same tail boundary, and both are caught
// OFF-BOX by ADR-0026 `--expect-tip`/`--since` against a fresh attested HEAD (tip=0 / a missing
// prior-observed HEAD => fail-closed at the relying party). A forged tail is NOT tolerated:
// it is well-formed JSON and so still fails the hash/sig/seq/prev checks.
//
// SEGMENTED CHAINS (R9 / ADR-0038). To bound /data, a chain rotates into sealed segments
// (<live>.NNNNNN) under a bounded retention window; verifySegmentedChain verifies the retained
// segments + the live file as ONE continuous chain (the rotation seam is link-continuous, NOT a
// per-boot reset). This extends boundary (a) by exactly one item: deletion/tamper of records in
// PRUNED segments — older than the retained window, no longer on disk — is, like tail truncation,
// caught only OFF-BOX (the attested HEADs of ADR-0025/0026). WITHIN the retained window every
// on-box guarantee above (interior edit/fork/reorder/illegal-reset/forged-sig and whole-subchain
// /segment deletion) is unchanged: the cross-segment prev_hash seed catches a deleted segment
// exactly as it catches a deleted middle subchain.

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

// chainSeed carries the running verification state ACROSS the files of a segmented chain (R9 /
// ADR-0038). A segmented chain is a sequence of sealed segments (<live>.NNNNNN) followed by the live
// file; verifySegmentedChain verifies them as ONE continuous chain by threading this seed from each file
// into the next. For a single, un-segmented file the seed is the genesis anchor (prev=zeroHash,
// expectSeq=0) with the torn tail tolerated — exactly the legacy single-file behavior.
type chainSeed struct {
	prev          []byte // running prev-hash carried in; the OLDEST retained file is anchored at zeroHash
	expectSeq     uint64 // running expected seq carried in (0 => the next seq==1 is a genesis/boot boundary)
	foundSince    bool   // whether the --since HEAD was already matched in an earlier file
	sinceSeq      uint64 // the seq at which it matched
	allowTornTail bool   // tolerate an unparseable FINAL record — true ONLY for the live file
}

// verifyChainSegment verifies one file of a (possibly segmented) chain starting from the seed `in`, and
// returns the verified count plus the seed carried OUT (prev=tip, the advanced expectSeq, and the
// since-match state) so the next file continues from it. The per-record checks — seq continuity,
// prev_hash linkage, canonical-hash recomputation, and Ed25519 signature, plus the ADR-0026 no-rewind
// `since` ancestry test — are IDENTICAL to the legacy single-file verifier; only the genesis anchor and
// the torn-tail tolerance are parameterized via the seed (R9 refactor: the security-critical loop body is
// unchanged). A torn FINAL record is tolerated only when in.allowTornTail (the live file); in a SEALED
// segment an unparseable final line is mid-chain corruption and fails closed.
func verifyChainSegment(path string, pub ed25519.PublicKey, domain string, since []byte, in chainSeed) (n int, out chainSeed, err error) {
	out = in // an absent/empty file passes the seed through unchanged
	f, e := os.Open(path)
	if e != nil {
		if os.IsNotExist(e) {
			return 0, out, nil // not yet created (first boot / a live file rotated-then-not-yet-written)
		}
		return 0, out, e
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // tolerate long Mode strings

	prev := in.prev             // running prev-hash; chains CONTINUOUSLY across boots (F5) AND segment seams
	expectSeq := in.expectSeq   // expected seq WITHIN the current per-boot subchain (carried across the seam)
	foundSince := in.foundSince // OR-ed across the chain's files
	sinceSeq := in.sinceSeq
	var tornTail error // a deferred unmarshal error on a line that MIGHT be an interrupted final record
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if tornTail != nil {
			// A prior line failed to parse and was NOT the last non-empty line, so it is mid-chain
			// corruption/tamper, never an interrupted tail. Fail closed.
			return n, out, tornTail
		}
		var r auditRecord
		if e := json.Unmarshal(line, &r); e != nil {
			// Possibly a torn FINAL record from a crash/power-loss mid-append: append() fsyncs every
			// record and rolls its tail back on a RETURNED Write/Sync error, but a power cut between the
			// write and that rollback can still leave an unparseable trailing fragment. DEFER the error —
			// it is tolerated ONLY if no further non-empty line follows AND in.allowTornTail (the live
			// file; checked after the loop). A FORGED record is well-formed JSON, so it still reaches the
			// crypto checks below and fails closed; this tolerates ONLY an unparseable trailing fragment
			// (the accepted, off-box-mitigated tail-truncation boundary — see the file header).
			tornTail = fmt.Errorf("record %d: malformed json: %w", n+1, e)
			continue
		}
		// seq resets to 1 at a per-boot boundary; otherwise it increments. But prev_hash chains
		// CONTINUOUSLY across boots (F5) AND across segment seams (ADR-0038) and is NOT reset here — so
		// deleting a whole middle subchain OR a whole sealed segment breaks the link (the next record's
		// prev_hash won't match the surviving prior record's hash). Genesis is the very first record of
		// the OLDEST retained file (seq=1, prev=0); a rotation seam is link-continuous, not a reset.
		if r.Seq == 1 {
			expectSeq = 1
		} else {
			expectSeq++
		}
		if r.Seq != expectSeq {
			return n, out, fmt.Errorf("record %d: seq=%d, expected %d (gap, reorder, or illegal reset)", n+1, r.Seq, expectSeq)
		}
		if !hexEqual(r.PrevHash, prev) {
			return n, out, fmt.Errorf("record %d (seq %d): prev_hash linkage broken (record/subchain/segment removed or reordered)", n+1, r.Seq)
		}
		sum := sha256.Sum256(canonical(r, prev, domain))
		if !hexEqual(r.Hash, sum[:]) {
			return n, out, fmt.Errorf("record %d (seq %d): hash mismatch (record body tampered)", n+1, r.Seq)
		}
		sig, e := hex.DecodeString(r.Sig)
		if e != nil {
			return n, out, fmt.Errorf("record %d (seq %d): bad signature hex: %w", n+1, r.Seq, e)
		}
		if !ed25519.Verify(pub, sum[:], sig) {
			return n, out, fmt.Errorf("record %d (seq %d): signature invalid (wrong key or forged record)", n+1, r.Seq)
		}
		if since != nil && !foundSince && bytes.Equal(sum[:], since) {
			foundSince, sinceSeq = true, r.Seq
		}
		prev = sum[:]
		n++
	}
	if e := sc.Err(); e != nil {
		return n, out, e
	}
	if tornTail != nil {
		if !in.allowTornTail {
			// A SEALED segment (or any non-live file) must end on a clean record boundary — an unparseable
			// final line there is mid-chain corruption, not an interrupted live append. Fail closed.
			return n, out, tornTail
		}
		// The deferred parse error was on the LAST non-empty line of the LIVE file at EOF — an
		// unacknowledged partial tail from an interrupted append. Tolerate it: the chain is valid through
		// record n. Required by the trust model (a partial tail must not false-brick the boot); mirrors
		// lastChainHash's tolerant re-anchoring on the same.
		log.Printf("verify-audit: tolerating an unparseable final record (interrupted-append partial tail; chain valid through %d record(s) in %s)", n, filepath.Base(path))
	}
	out.prev = prev
	out.expectSeq = expectSeq
	out.foundSince = foundSince
	out.sinceSeq = sinceSeq
	return n, out, nil
}

// verifyChainState verifies a SINGLE chain file from genesis (prev=zeroHash), tolerating an interrupted
// partial tail. Its signature and behavior are unchanged from before the R9 segment refactor, so the
// single-file callers (verifyChain, an offline verify-audit on one explicit file, the existing tests) are
// untouched. The TIP it returns binds the verified log to a quote's reported HEAD (ADR-0025); foundSince
// is the no-rewind primitive (see verifyChainSegment / cmdVerifyAudit). The boot gate / no-rewind verdict
// uses verifySegmentedChain, which threads MANY files through verifyChainSegment.
func verifyChainState(path string, pub ed25519.PublicKey, domain string, since []byte) (n int, tip []byte, sinceSeq uint64, foundSince bool, err error) {
	n, out, err := verifyChainSegment(path, pub, domain, since, chainSeed{prev: zeroHash, allowTornTail: true})
	if err != nil {
		return n, nil, 0, false, err
	}
	if n == 0 {
		return 0, nil, 0, false, nil // empty/absent chain — genesis, nothing to verify
	}
	return n, out.prev, out.sinceSeq, out.foundSince, nil
}

// verifySegmentedChain is the boot-gate / no-rewind driver over a possibly-segmented chain (R9 /
// ADR-0038). It verifies the sealed segments (<livePath>.NNNNNN, numeric-ascending) followed by the live
// file as ONE continuous chain: the OLDEST retained file is anchored at prev=zeroHash and each file's
// verified tip seeds the next file's prev, so deletion of a whole segment across the seam breaks the SAME
// prev_hash linkage the single-file verifier already enforces (whole-subchain-deletion detection is
// preserved across the seam). Torn-tail tolerance is scoped to the LIVE file only; a torn tail in a sealed
// segment fails closed. ADR-0038 detection-boundary trade: tamper/deletion of records in PRUNED segments
// (older than the retained window, no longer on disk) is caught OFF-BOX (ADR-0025/0026 attested HEADs),
// exactly as the tail-truncation boundary already is; WITHIN the retained window on-box detection is
// unchanged. For a chain with NO sealed segments this verifies exactly the live file == legacy behavior.
// Returns the live tip + the OR-ed since-match across all files.
func verifySegmentedChain(livePath string, pub ed25519.PublicKey, domain string, since []byte) (n int, tip []byte, sinceSeq uint64, foundSince bool, err error) {
	dir := filepath.Dir(livePath)
	base := filepath.Base(livePath)
	seed := chainSeed{prev: zeroHash}
	total := 0
	// Sealed segments first, oldest -> newest; each must be COMPLETE (no torn tail tolerated).
	for _, num := range listSegments(dir, base) {
		seed.allowTornTail = false
		cnt, out, e := verifyChainSegment(segmentPath(dir, base, num), pub, domain, since, seed)
		total += cnt
		if e != nil {
			return total, nil, 0, false, fmt.Errorf("segment %06d: %w", num, e)
		}
		seed = out
	}
	// The live file last; tolerate an interrupted partial tail here only.
	seed.allowTornTail = true
	cnt, out, e := verifyChainSegment(livePath, pub, domain, since, seed)
	total += cnt
	if e != nil {
		return total, nil, 0, false, e
	}
	if total == 0 {
		return 0, nil, 0, false, nil // empty/absent chain — genesis
	}
	return total, out.prev, out.sinceSeq, out.foundSince, nil
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
	sinceArg, expectTip, rest, err := parseVerifyArgs(args[1:])
	if err != nil {
		log.Fatalf("verify-audit: %v", err)
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

	n, tip, sinceSeq, foundSince, err := verifySegmentedChain(chain, pub, domain, since)
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

// parseVerifyArgs parses the verify-audit argv after the chain: the optional pubkey positional and the
// --since=/--expect-tip= flags. It FAILS CLOSED on every malformed flag rather than dropping a requested
// check and exiting 0 (false assurance): an unknown flag, more than one positional, OR a present-but-EMPTY
// --since=/--expect-tip= — the empty case guards the offline relying-party footgun where an unset/typo'd
// shell var (`--since=$TIP` with $TIP unset) expands to `--since=` and would otherwise silently downgrade a
// requested no-rewind/tip binding to a plain integrity check. (The all-zero genesis form is `--since=0000…`,
// 64 hex zeros, NOT empty.) Pure so the fail-closed parsing is unit-testable (cmdVerifyAudit log.Fatalf's it).
func parseVerifyArgs(args []string) (sinceArg, expectTip string, rest []string, err error) {
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "--since="):
			sinceArg = strings.TrimPrefix(a, "--since=")
			if strings.TrimSpace(sinceArg) == "" {
				return "", "", nil, fmt.Errorf("--since= has an empty value (a requested no-rewind check must not be silently skipped — did a shell var expand to empty? genesis is --since=<64 hex zeros>)")
			}
		case strings.HasPrefix(a, "--expect-tip="):
			expectTip = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(a, "--expect-tip=")))
			if expectTip == "" {
				return "", "", nil, fmt.Errorf("--expect-tip= has an empty value (a requested tip check must not be silently skipped — did a shell var expand to empty?)")
			}
		case strings.HasPrefix(a, "-"):
			// A misspelled flag (e.g. --sinc=) must NOT be silently dropped into rest[] and ignored —
			// that would skip a REQUESTED no-rewind/tip check yet exit 0 (false assurance). Fail closed.
			return "", "", nil, fmt.Errorf("unknown flag %q (expected --since=<head-hex|@file> or --expect-tip=<head-hex>)", a)
		default:
			rest = append(rest, a) // the optional pubkey positional
		}
	}
	// At most ONE positional after the chain (the pubkey). Extra positionals are a typo/misuse, not a
	// silently-ignored second key — fail closed so a requested check can't be quietly skipped.
	if len(rest) > 1 {
		return "", "", nil, fmt.Errorf("unexpected extra argument(s) %v (only one pubkey positional is accepted)", rest[1:])
	}
	return sinceArg, expectTip, rest, nil
}

// chainDomain infers the per-chain domain (F4) the verifier must use from the chain's path.
// The on-box chains are the collector provenance (/data/bulkhead/audit), the broker decision
// chain (/data/bulkhead/audit-broker), and the router routing-decision chain (ADR-0027,
// /data/bulkhead/audit-router); the domain is the VERIFIER's belief about which chain this is,
// never read from the record (so a transplant fails). Overridable for offline use via
// BULKHEAD_AUDIT_DOMAIN.
func chainDomain(chain string) string {
	if d := os.Getenv("BULKHEAD_AUDIT_DOMAIN"); d != "" {
		return d
	}
	switch {
	case strings.Contains(chain, "audit-router"): // ADR-0027: the router routing-decision chain
		return "router"
	case strings.Contains(chain, "audit-broker"):
		return "broker"
	case strings.Contains(chain, "audit-egress"): // ADR-0034: the egress-proxy decision chain
		return "egress-proxy"
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
