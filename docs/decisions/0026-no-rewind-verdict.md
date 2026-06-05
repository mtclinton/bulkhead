# ADR-0026: the no-rewind verdict — verify-audit ties the quote to the chain history

Status: Accepted
Date: 2026-06-05
Relates to: ADR-0017 (signed audit chains + verify-audit), ADR-0019 (the quote), ADR-0025 (the quote
binds the box's REPORTED chain HEADs, non-repudiably). Closes the loop ADR-0025 explicitly deferred.

## Context

ADR-0025 made the box's reported audit-chain HEADs non-repudiable, replay-proof, and tamper-evident
under a fresh-nonce TPM quote — but it deliberately PUNTED the actual no-rewind/no-fork verdict to "a
separate relying-party step: run verify-audit on the shipped chain logs (continuity), confirm each tip ==
the bound HEAD, and confirm it has not regressed below a prior observation." That step did not yet exist
as a command, so the no-rewind story was stated but not executable.

## Decision

`verify-audit` gains two optional inputs that render the verdict, fail-closed:

- **`--expect-tip=<head-hex>`** — the verified chain's tip must equal a HEAD the quote bound (ADR-0025).
  Since `attest verify` already made that HEAD non-repudiable, a match proves the continuity-verified log
  IS the one the quote attested — joining the quote's unforgeable current-HEAD claim to the hash-chain
  integrity proof.
- **`--since=<prior-head-hex|@file>`** — a HEAD the relying party recorded earlier must be a VERIFIED
  ANCESTOR of the tip. The genesis/all-zero value is vacuously an ancestor (CLEAN). A non-genesis value
  must appear as a verified record's hash; if it does not, the verdict is **REWOUND/FORKED** (exit 1).

The no-rewind primitive is **hash-ancestry, not seq-comparison.** `verifyChainState` (the walk extracted
from `verifyChain`, which is now a thin wrapper — zero caller churn) verifies the records form ONE
continuous linear chain and reports the tip plus whether a `since` HEAD appears as a record's
cryptographically VERIFIED hash. Because the chain is linear and hash-linked, a record whose hash equals
the prior-observed HEAD forces its entire prefix to be byte-identical, so the tip provably descends from
that observation — no rewind or fork at or below it. A fork/truncation that drops the observation cannot
reproduce its hash and is detected. Crucially this is **cross-boot-safe**: `seq` resets per boot (ADR-0017
F5) and is therefore used only for diagnostics, never the verdict — the hash chain is the ordering.

With neither flag, behavior is unchanged: integrity-only, exit non-zero on a broken record (the ADR-0017
boot gate). The OK line now also prints `tip=<hex>` for capture. Flag parsing is fail-closed: a
misspelled flag (e.g. `--sinc=`) or an extra positional is rejected with a non-zero exit rather than
silently dropped, so a requested verdict can never be quietly skipped (adversarial-review fix).

The end-to-end no-rewind proof a relying party runs: `attest verify` (the quote → a non-repudiable,
fresh current HEAD) + `verify-audit <log> --expect-tip=<that HEAD> --since=<prior observation>` (the log
is continuity-clean, IS the attested one, and extends the prior observation).

## Verification

`go build`/`vet`/`test`/`test -race` green. Unit test `TestVerifyChainStateTipAndAncestry`: the tip is
the last record's hash; a prior HEAD that is a real record's verified hash is found with its seq
(including an advanced observation with records above it); a HEAD not in the chain is not found (no
false-positive ancestry). Live swtpm (`make verify-attest`): 26.1 the quote's attested control HEAD ==
the verify-audit tip; 26.2 `--since` a prior-observed HEAD renders no-rewind CLEAN; 26.3 `--since` a HEAD
not in the chain fails closed as REWOUND/FORKED.

## Seam

- The verdict is RELATIVE to a relying-party prior observation (TOFU): it proves the chain has not been
  rewound/forked AT OR BELOW the recorded HEAD. A fork strictly ABOVE the last observation (new divergent
  records the relying party never saw) is outside one observation's reach — the relying party tightens
  this by observing more often. `--expect-tip` bounds the top end to the attested current HEAD.
- verify-audit verifies the SHIPPED log; getting the box to ship a complete, current log is the operator
  transport's job (a box can withhold a log, which `--expect-tip` against a fresh quote surfaces as a
  tip mismatch). The signing key is resolved as before (explicit arg > sealed seed > sibling
  audit-pub.txt), so the integrity + ancestry proofs hold under the same key trust as ADR-0017.
- A natural follow-up is a single relying-party command that performs `attest verify` + per-chain
  verify-audit and emits one combined machine-readable verdict.
