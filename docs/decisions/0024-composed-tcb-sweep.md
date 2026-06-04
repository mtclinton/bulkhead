# ADR-0024: Composed-system TCB sweep — the authorization matrix + the digest-read atomicity fix

Status: Accepted
Date: 2026-06-04
Relates to: ADR-0004 (E0–E3 + the TCB model), ADR-0016 (the control socket), ADR-0017 (signed chains),
ADR-0019..0023 (the attestation line). A CONSOLIDATION pass, not a feature.

## Context

After the attestation line (ADR-0019..0023) the TCB spans the collector (the single bpf map writer + the
control socket + the audit signer) + the broker (User=root, human-gated delegation/EXPAND/grant-once) +
13 control verbs + 3 broker verbs + 2 signed chains + the gates. Each ADR asserted its OWN gate, but no
review had validated the WHOLE authorization surface TOGETHER — and the safety of the stack rests on a
cross-verb invariant asserted per-verb but never checked over the union. A composed-system adversarial
sweep (survey the authorization matrix → per-dimension finders → adversarial refutation → synthesis)
did so.

## Findings

**THE MASTER INVARIANT HOLDS.** The control socket is `0660 root:root`; `handleControlConn` requires the
kernel-attested `SO_PEERCRED` uid==0 + `SO_PEERPIDFD` cgroup. The per-verb gates compose correctly:
- **SELF-verbs** (`EGRESS-SET-SELF`/`EGRESS-CLEAR-SELF`/`GRANT-CLEAR-SELF`): `isAgentCgroup` ALLOWLIST
  (agent cgroups only; write only the kernel-attested SELF cgid + only `egress_policy`/`grant_once`).
- **`TCB-REGISTER-BROKER`**: `isBrokerCaller` exact `filepath.Clean` match (the broker cgroup only).
- **DENYLIST verbs** (`ENFORCE-SET` = the master kill switch + the 6 attest verbs): `!isAgentCgroup`
  (reject agents, allow any non-agent uid-0). This is a denylist, not a strict TCB allowlist — but the
  sweep confirmed the only non-agent uid-0 / root-group callers are the broker (TCB), the static
  enforce / gate / firewall / router-bind oneshots (NO untrusted input), and `tailscale-up` (read-only
  attest gates). The untrusted-input ROUTER runs `DynamicUser=yes` (unprivileged — cannot open the
  socket). So no non-TCB / untrusted-input process reaches the kill switch; the invariant holds against
  the composition.

Also held: the anchored agent-cgroup regex (no traversal), `reverifyCgroup` re-stat (no inode-recycle),
grant-once TTL + `ExecStopPost` cleanup, domain-tagged chains (no cross-chain transplant), the ADR-0023
`doAttestExtend` idempotency, `gatePosture` requiring BOTH E0+E2.

**ONE MUST-FIX (medium, folded here).** `attestDigest()` and `gatePosture()` read `enforce_flags` +
`tcb_cgroups` WITHOUT `controlMu`, while the WRITERS (`ENFORCE-SET`, the self-verbs, `TCB-REGISTER-BROKER`,
gc) HOLD it. A concurrent `ENFORCE-SET` (an operator disarm, or a collector-restart `PartOf` cascade)
could interleave mid-loop, so the digest / gate predicate would encode a TORN, never-real posture
(usually fail-closed — a false-negative gate — but worst-case a false-positive gate if the mixed state
looks armed). This is exactly the cross-pillar atomicity seam per-ADR review missed.

## Decision

`controlMu` now wraps the multi-key reads in `attestDigest` + `gatePosture` AND gc's bounded map deletes,
making `controlMu` the COMPLETE read/write serialization point for `enforce_flags`/`tcb_cgroups` (the
atomicity invariant is documented on the `controlMu` declaration). The lock is taken BEFORE `tpmMu` in
the attest callers (`attestDigest` runs before `tpmMu.Lock()` in `doAttestExtend`/`doAttestQuote`), so it
never nests with the TPM lock. gc holds it only across the bounded (≤1024-entry) map mutations, not the
cgroup-fs scan. No TCB authority change — purely an atomicity fix.

## Verification

`go build`/`vet`/`test` + `go test -race` (CGO on) green — no data race, no deadlock against the concurrent
`ENFORCE-SET`/gc paths. Live swtpm `verify-attest`: the full 33-check suite (quote / verify / EK-rooting /
gate / self-check) stays green — the digest/gate now reads under `controlMu` with no behavioral change on
a quiescent box.

## Seam

- `controlMu` is collector-process-local; the broker is a separate process but does NOT write the bpf
  maps directly (it delegates through the control socket → the collector under `controlMu`), so one
  process-local mutex IS the complete serialization point. (Confirmed in the sweep.)
- The denylist (vs a strict TCB allowlist) on the kill-switch verbs is sound TODAY because every
  non-agent uid-0 caller is either TCB or untrusted-input-free; a FUTURE root unit that handles
  untrusted input would need a TCB allowlist. Recorded as a standing invariant to preserve.
