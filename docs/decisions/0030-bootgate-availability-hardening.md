# ADR-0030: boot-gate availability hardening — the false-brick boundary

Status: Accepted
Date: 2026-06-06
Relates to: ADR-0008 (the sealed audit seed + the F5 boot gate), ADR-0026 (the no-rewind /
`--expect-tip` verdict — the OFF-BOX anchor), ADR-0027 (the router chain — the 4th verified chain),
ADR-0028 (tpm2 sealing), ADR-0029 (the transactional append, whose in-process rollback this completes for
the crash path). Closes the AVAILABILITY (false-brick) findings of the 2026-06-06 boot-gate audit; the
gate's integrity core (unseal-ordering, 4-chain coverage, fail-closed-on-tamper) was audited SOUND and is
unchanged.

## Context

The F5 boot gate (`bulkhead-verify-audit.service` → `verifyChainState`) refuses the boot if any persisted
signed chain is broken. An adversarial audit confirmed the gate detects every TAMPER it should
(in-place edit, fork, reorder, illegal seq reset, forged signature, interior-record / whole-MIDDLE-subchain
deletion — the continuous cross-boot prev_hash linkage breaks) and found NO way for a tampered chain to
PASS. The residue was entirely on the AVAILABILITY axis — legitimate transient states that FALSE-BRICK an
honest box — plus the precise on-box-vs-off-box detection boundary, which was implicit:

1. **Interrupted-append torn tail.** ADR-0029 made `append()` transactional, but its rollback only fires on
   a RETURNED Write/Sync error. A crash/power-loss between the write and that rollback leaves an
   UNPARSEABLE trailing fragment. `verifyChainState` hard-failed on the `json.Unmarshal` error → the NEXT
   boot bricked. An unclean shutdown must not brick an honest appliance.
2. **Seed loss while chains survive.** The seal script (`bulkhead-seal-audit-key`) self-heals an
   absent/unreadable seed by minting a FRESH one. If signed chains from a prior boot survive (a restore that
   excluded the seed, a TPM clear / PCR-7 change), the new pubkey makes every surviving record fail
   verification → the boot bricks with a cryptic per-chain "signature invalid". Correct fail-closed for
   tamper, but a confusing brick for a recoverable operator error.
3. **Whole-file / latest-tail erasure is undetectable ON-BOX.** An attacker with `/data` write who deletes a
   WHOLE chain (or truncates its latest tail) passes the on-box gate — it is byte-indistinguishable from a
   legitimate first boot / empty chain. A box cannot non-circularly verify its own deletable history against
   its own deletable anchor; this is an information-theoretic limit, not a code bug. It was already mitigated
   off-box but not stated as the deliberate boundary.

A related offline-CLI footgun (an empty `--since=`/`--expect-tip=` silently skipping a requested no-rewind/
tip check) was fixed first as pure fail-closed tightening (commit `1e76ea0`).

## Decision

1. **Tolerate exactly ONE unparseable FINAL record at EOF.** `verifyChainState` DEFERS a `json.Unmarshal`
   error: it is tolerated only if no further non-empty line follows (a crash-interrupted partial tail), and
   fails closed if any non-empty line follows it (mid-chain corruption). A FORGED tail is well-formed JSON,
   so it still reaches — and fails — the hash/sig/seq/prev checks; tolerance covers ONLY an unparseable
   fragment. This mirrors `lastChainHash`'s already-tolerant re-anchoring and is the same tail boundary as #3.
2. **Refuse to mint a fresh seed over surviving chains.** Before generating a new seed (both `plain` and
   `tpm2` paths), the seal script checks for any non-empty chain on `/data` and, if found, stops with a
   LOUD, self-documenting "SEALED AUDIT KEY LOST" message, leaving all state untouched for recovery. The
   operator restores the seed from backup and reboots (the script then finds it valid and the box boots),
   or sets `BULKHEAD_SEAL_FORCE_NEW=1` to authorize a fresh identity (explicitly discarding the ability to
   verify prior history). First boot / a wiped `/data` has no chains, so this never blocks a legitimate mint.
3. **Document the detection boundary.** The `verify.go` header now states explicitly what the on-box gate
   does and does NOT detect, and that whole-file/tail erasure (and the tolerated torn tail) are deliberately
   caught OFF-BOX by ADR-0026 `--expect-tip`/`--since` against a fresh attested HEAD (tip=0 / a missing
   prior-observed HEAD ⇒ fail-closed at the relying party).

## Verification

- **Torn tail:** `TestVerifyChainTornTail` — (a) an unparseable trailing fragment is tolerated (chain
  verifies through its committed tail); (b) a valid final record with no trailing newline still fully
  verifies; (c) a torn record MID-chain fails closed; (d) a forged (well-formed, bad-sig) final record fails
  closed. `go build/vet/test -count=1` + `-race` green.
- **Empty flag:** `TestParseVerifyArgs` — empty/whitespace `--since=`/`--expect-tip=` are usage errors;
  unknown flag + extra positional still fail closed; valid forms parse.
- **Seal refuse-to-mint:** `sh -n` clean; the predicate keys only on a non-empty chain file existing, so it
  is inert on first boot and on a normal reboot (the seed-present early-exit fires first). Exercised live by
  the re-pin's `verify-e0`/`verify-hbd`/`verify-yocto-router` (a normal armed boot mints/keeps the seed and
  the gate passes — confirming the new predicate does not perturb the happy path).

## Seam

- **On-box erasure detection** would need a TPM-sealed monotonic high-water-mark (any non-sealed anchor is
  writable by the same `/data`-write attacker). Deferred deliberately — off-box `--expect-tip` is the
  designed mitigation; a sealed counter is bare-metal-meaningful future work.
- **Seed redundancy** (atomic-write + a redundant copy) would reduce the likelihood of the seed-loss case in
  the first place — orthogonal to the refuse-to-mint guard, not done here.
