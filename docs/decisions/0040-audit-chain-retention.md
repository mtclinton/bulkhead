# ADR-0040: Bounded-retention segment rotation for the signed audit chains

Status: Accepted — verifier + signer rotation + per-tier config shipped; live-verify on the production image pending
Date: 2026-06-16
Pillar: provenance (the signed audit chains)
Relates to: ADR-0008 (the sealed signing seed), ADR-0017 (the control-write chain), ADR-0025/0026 (audit HEADs in the quote + the no-rewind verdict), ADR-0030 (the boot-gate detection boundary this extends), ADR-0034 (the egress chain — the highest-volume tier). Addresses security-review finding R9.

## Implementation status

Shipped (code + unit tests, all three Go modules green):

- **The verifier follows segments (landed first).** `verifySegmentedChain` verifies the sealed segments (`<live>.NNNNNN`) + the live file as ONE continuous chain. Refactored out of the single-file verifier with the security-critical per-record loop **unchanged**; single-file callers are byte-identical. This shipped before any signer rotates, so no box can ever boot into a segment its verifier cannot follow (the R8 lesson: a careless chain change bricks the box two boots later).
- **The signers rotate** (collector ×2 chains, broker, router, egress-proxy). `append()` seals the live file into a numbered segment once it reaches `BULKHEAD_AUDIT_SEGMENT_BYTES`, before writing the record; `pruneSegments()` keeps the newest `BULKHEAD_AUDIT_SEGMENTS_KEEP`. The seven rotation helpers are byte-identical across `src/collector`, `src/proxy`, `src/router`.
- **Per-tier config** in the `*-data.conf` drop-ins: 8 MiB segments, keep 1 → each chain caps at 16 MiB; the collector's two chains + broker + router + egress = 80 MiB < the 100 MB `/data` partition.

Pending: a live rotate-across-reboot test on the production image (`make verify-*`).

## Context and problem statement

The five signed, hash-chained audit logs (collector provenance + control, broker, router, egress-proxy) are append-only and share one **fixed-size** `/data` partition (`--fixed-size 100M`, outside the RAUC A/B slots). Nothing bounded their growth. Two failure modes followed:

- **Cross-tier denial (R9).** A compromised agent that drives its egress chain hard fills `/data`. Every chain's `append()` is transactional and fail-closed — an `ENOSPC` write fails, the record is not durable, and the proxy/router/collector drop the action rather than emit an un-audited one. So one noisy tier starves *every other* tier into refusing to act: a self-inflicted, structural denial of the whole appliance.
- **Unbounded boot-verify.** The boot gate re-verifies every persisted record on every boot; an ever-growing chain means an ever-growing boot cost and an unbounded `lastChainHash`/`lastChainTip` read.

Bounding a fixed partition that holds append-only logs requires either pruning old history or the fail-closed DoS above. There is no third option: choosing to fix R9 *is* choosing bounded on-box retention.

## Decision drivers

- **Integrity first.** Bounding `/data` must not quietly weaken the chain's on-box tamper-evidence within the history it still holds.
- **No false brick.** The R8 lesson dominates: rotation/verification logic that bricks a fielded box on the next boot is worse than the DoS it fixes. Fail *open to availability* on rotation faults, never closed.
- **Per-tier blast-radius isolation.** The egress tier (the DoS source) must not be able to consume the bytes the collector/broker/router chains need.
- **Smallest risk surface.** The audit chain is TCB; prefer a code-only change over a fielded-filesystem migration.

## Considered options

A three-way design panel evaluated:

1. **Bounded-retention segment rotation (chosen).** Seal the live file into numbered segments, keep a bounded window, prune the rest. The verifier threads each segment's verified tip into the next file's prev-hash seed, so a deleted segment breaks the *same* linkage that already catches a deleted middle subchain. Keeps the exact on-box guarantee within the retained window; moves only *pruned*-segment detection off-box.
2. **Genesis-with-anchor rotation.** The boot gate verifies only the live segment from a signed rotation-anchor and never opens the sealed segments. Rejected: it *deliberately* stops detecting deletion of a sealed predecessor segment on-box — a real reduction of the current whole-middle-subchain-deletion guarantee. (Its self-describing-anchor idea was considered as additive defense-in-depth and dropped: it adds a new signed record shape and golden-vector churn across three modules for a benefit the threaded seed already provides.)
3. **ext4 project-quota + signed `pruned-through` watermark.** A hard kernel backstop, but it needs an in-field filesystem-feature migration (`tune2fs -O quota,project`, `quotacheck`, a new boot-ordered unit) on an already-provisioned `/data`, plus a signed watermark the boot gate must trust — the highest brick/bypass surface of the three. The quota idea is a sound *future* hardening that can sit on top of option 1 without touching the chain code.

## Decision

Adopt **option 1**. A chain is `<live>` plus zero or more sealed segments `<live>.NNNNNN` (zero-padded width-6, so lexical order = numeric order).

- **Rotation is link-continuous.** On rotation `a.prevHash`/`a.seq` are **not** reset, so the first record of the fresh live file links to the sealed segment's tip and continues the seq. A rotation seam is therefore *not* a per-boot boundary; the verifier proves it with the existing prev-hash check.
- **The retained-head anchor.** After pruning, the oldest *retained* segment's first record links to a now-deleted predecessor. The verifier accepts that one record's prev/seq as the on-box anchor **iff** the oldest segment number > 1 (the head was pruned); a still-present segment `000001` is genesis and stays strictly anchored at zero. The signature still binds the accepted prev, so an attacker can only present a contiguous, legitimately-signed *suffix* (= head truncation) — never a forge or reorder, and deletion of any *middle* retained segment still fails closed.
- **R1 — rotation never becomes a denial.** `rotate()` always leaves the writer a usable file handle: on a `Sync`/`Rename` fault the live file is untouched and still open; on a reopen fault after a successful rename it un-renames; `append()` treats any rotation error as "log and keep writing the current file". A failed prune is non-fatal. `segKeep` is clamped to ≥ 1 so the live file always links to a present segment.
- **Cross-boot + attest.** `lastChainTip` resolves the tip as live-else-newest-segment, so the cross-boot prev-hash seed (ADR-0008/F5) and the quoted HEADs (ADR-0025) bind the real tip even in the rename→first-append window.
- **Default off; appliance on.** Rotation is disabled unless `BULKHEAD_AUDIT_SEGMENT_BYTES` is set (dev/Buildroot unchanged); the appliance drop-ins enable it per tier.

## Consequences

### Positive

- `/data` is bounded per chain at `(segKeep+1) × rotateBytes`; the five chains total 80 MiB < 100 MB, so R9's cross-tier denial is structurally impossible — the egress tier cannot reach the other chains' bytes.
- On-box tamper detection within the retained window is **unchanged**: interior edit/fork/reorder/illegal-reset/forged-sig and whole-subchain *or* whole-segment deletion all still fail the boot gate closed.
- Boot-verify cost is bounded to the retained bytes.

### Negative / costs — the one new off-box-only item

- **Pruned-segment detection moves off-box.** Tamper or deletion of records in segments older than the retained window (no longer on disk) is no longer reconstructable on-box. This is a deliberate, documented **extension of the ADR-0030 tail-truncation boundary** to a bounded head: both are caught off-box by the ADR-0025/0026 attested HEADs (a relying party whose prior-observed HEAD has been pruned away gets `foundSince=false` → a rewind/fork verdict). It is the audit chain's only narrowed on-box guarantee, and choosing to fix R9 (bound a fixed partition holding append-only logs) necessarily entails it.
- The three byte-identical copies of the rotation helpers must not drift (mitigated: a `diff`-verified identical block + a per-module `segmentPath` golden alongside the existing `canonical()` golden).

### Owner sign-off

The pruned-segment narrowing above is an owner-level decision (it changes an on-box guarantee). It is accepted here as consistent with the existing ADR-0030 boundary and inherent to the requested R9 fix. The owner should confirm the off-box archival pull is operating at a cadence faster than the prune cadence (8 MiB segments, keep 1) before relying on full forensic depth; until then the conservative knobs keep rotation bounding growth while retaining a full segment of recent history on-box. Raising `BULKHEAD_AUDIT_SEGMENTS_KEEP` widens the on-box window at a known `/data` cost (respect the `Σ (keep+1)×bytes < 100 MB` budget).

### Residual risks

- **Rename-then-crash empty live file.** Handled by `lastChainTip` seeding from the newest segment (never re-anchoring at genesis) and tested; on the DynamicUser tiers the cross-boot `ExecStartPre` makes sealed segments group-readable so the next boot's uid can seed from them.
- **A 6th+ chain added without re-budgeting** breaks `Σ (keep+1)×bytes < 100 MB`. Documented beside the threshold constant.

## Related ADRs

ADR-0030 (the tail boundary this extends to a bounded head), ADR-0025/0026 (the off-box attestation that catches what pruning moves off-box), ADR-0008 (the sealed seed + cross-boot continuation), ADR-0034 (the egress chain, R9's source). Distinct from ADR-0038 (confidential computing, rejected).
