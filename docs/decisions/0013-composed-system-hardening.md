# ADR-0013: Composed-system hardening (second adversarial review)

Status: Accepted
Date: 2026-06-03
Relates to: ADR-0004 (E0–E3 enforce + the TCB model), ADR-0006/0007 (broker + approval-gate),
ADR-0008 (sealed audit seed), ADR-0010 (NARROW), ADR-0011 (one-shot grant), ADR-0012 (TCB-context
GC). Supersedes nothing; closes cross-slice holes the per-slice designs each missed.

## Context

A second whole-system adversarial review (7 dimensions, 3-vote refutation, ~56 agents) of the
COMPOSED system — the surface accreted since the first review (ADR-0010..0012): the BPF object
change, the GC, five broker action paths, three locks, two audit chains — confirmed **8 defects
(6 HIGH)**, two reproduced empirically against the real `verifyChain`/`canonical`. The individual
slices are each internally sound, but their *composition* across the two map-sharing processes
(collector + broker) did not hold to the invariants the ADRs/threat-model advertise. This ADR
records the fixes; all are pure-Go / unit-level (the verified E0–E3 BPF object is unchanged).

## Decision (fixes, by finding)

**F1/F5 — `tcb_cgroups` recycle escape (HIGH, fail-DANGEROUS).** The broker self-registers its
cgid into `tcb_cgroups` once and never deletes it; an independent broker re-activation leaves a
STALE cgid whose dead inode can be recycled onto a `bulkhead-agent@` jail — granting that agent
full E0–E3 TCB exemption (the one per-cgroup map with no recycle defense). FIX: the collector GC
now **reconciles `tcb_cgroups`** each pass (`reconcileTCB`, gc.go) — pruning any entry that is not
{root, the collector, the LIVE broker} (broker resolved by the same `system.slice/
bulkhead-broker.service` path the broker self-registers). DELETE-ONLY and FAIL-SAFE (if root+
collector can't be resolved it prunes nothing). A stale broker cgid recycled onto an agent is
removed within one GC interval.

**F2 — broker de-TCB on collector restart (HIGH, fail-closed).** `brokerSelfRegisterTCB` runs once
at broker startup; the collector `os.RemoveAll(pinDir)` rebuilds a fresh `tcb_cgroups` (root+
collector only) on every `run`, and the broker wasn't restarted — so after a collector restart the
broker is silently non-TCB and, once E0 is armed, every gated action breaks. FIX: `PartOf=
bulkhead-collector.service` on `bulkhead-broker.service`, so a collector restart restarts the
broker, which re-self-registers against the new map (E0 is reset to observe by the same restart, so
the self-register `bpf()` succeeds). The F1 GC reconcile is the backstop.

**F3 — one-shot grant inherited across inode recycle (HIGH, fail-DANGEROUS).** A crash (skips
`ExecStopPost`) + E0-off + a new agent reusing the inode within the TTL → the GC KEEPS the grant
(inode live again) and the new agent inherits an E1/E3 escalation it never requested (the GC can't
fix this — no occupant provenance). FIX: the agent template gains an `ExecStartPre=-+… grant-once
clear self` BEFORE its payload forks, so a freshly-launched agent wipes any inherited grant at
startup (E0-off; under E0-armed a new agent can't start at all). A fresh agent has no legitimate
grant yet, so clearing is always safe.

**F4 — cross-chain transplant (HIGH).** Both chains load the same sealed seed and `canonical()`
had no domain tag, so a broker record verified as a collector record (a /data attacker could
transplant validly-signed subchains). FIX: `canonical(r, prev, domain)` binds a per-chain DOMAIN
("collector"/"broker") into the signed hash; the domain is supplied by the VERIFIER (which knows
which chain it is checking via `chainDomain`/`BULKHEAD_AUDIT_DOMAIN`), never read from the record —
so a transplant fails.

**F5b — middle-subchain deletion undetectable (HIGH).** `verify-audit` re-anchored at every
`seq=1/prev=0`, so deleting whole per-boot subchains left a valid chain. FIX: the hash chain now
**continues across boots** — `openAuditLog` seeds the new boot's first `prev_hash` from the prior
boot's last hash (`lastChainHash`), and `verifyChain` no longer resets `prev` at `seq=1` (seq still
resets per boot, but `prev_hash` chains continuously), so deleting a middle subchain breaks the
linkage. *Tail*-truncation detection still requires off-box head anchoring (the appliance exposes
its head for an external monitor) — left as a documented seam; the threat-model wording is corrected.

**F6 — DELEGATE's parent read not serialized vs NARROW (HIGH).** Delegate computed the child mask
under `launchMu` only; an operator `narrow` (on `egressMu`) could interleave between the parent-mask
read and the slow `launchChild`, birthing the child holding the just-revoked class. FIX: take
`egressMu` around delegate's `reverifyCgroup`+`lookupEgressMask`+child-mask computation (snapshot
under `egressMu`, launch outside it; lock order `launchMu`→`egressMu`, no inversion).

**F7 — best-effort audit append (MEDIUM).** A gated action could take effect and reply `OK` while
its signed record silently failed to land. FIX: `recordDecision`/`recordNarrow` return the append
error; on a post-side-effect append failure the broker replies `ERR audit` and logs loudly — the
audit record is now load-bearing, not advisory.

**Nits.** `BULKHEAD_THRESHOLD` gains a floor (`thresholdFloor`, min 64) so a 0/negative value can't
open the denial-of-wallet gate; the ADR-0011 "bytecode textually unchanged" claim is corrected
(source-level invariant, not byte-for-byte; E0 still has zero `grant_once` refs in the disasm).
DEFERRED (noted, not built): off-box audit-head anchoring; auditing the GC's own prunes; correlating
a grant consume to its approval; an instant (vs ≤GC-interval) agent-in-TCB guard.

## Verification

Host `go test -race` (both modules) green, with new tests: `TestVerifyChainDetectsSubchainDeletion`
(F5b), `TestVerifyChainRejectsWrongDomain` (F4), `TestThresholdFloor` (nit), plus the existing
audit/GC/broker suites updated for the new signatures. qemu regression — the existing gated-action
harnesses (approve/delegate, expand, narrow, grant, gc) still pass, exercising the new
domain-tagged `canonical()` + the boot-gate `verify-audit` + the `egressMu`-serialized delegate +
the startup grant-clear live. A focused harness adds: the broker survives a collector restart and
still serves a gated action (F2/PartOf); the GC `reconcileTCB` prunes a stale `tcb_cgroups` entry
while keeping the live broker (F1/F5); and a broker-chain record fails `verify-audit` under the
collector domain (F4).

## Verdict carried forward

The review's verdict was **fix-then-ship**: the architecture is sound; these were composition
holes, not a redesign. The single most dangerous (`tcb_cgroups` recycle) is now defended like every
other per-cgroup map — closing "the one map left undefended against the exact recycle threat the
project built three mechanisms to stop elsewhere."
