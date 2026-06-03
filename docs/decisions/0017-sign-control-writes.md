# ADR-0017: Sign the collector's control-socket authority writes

Status: Accepted
Date: 2026-06-03
Relates to: ADR-0008 (measured boot + the sealed audit seed), ADR-0013 (composed-system audit
hardening — the per-chain domain F4, cross-boot linkage F5), ADR-0016 (the collector control
socket — the bpf()-write chokepoint for non-TCB callers). Closes the ADR-0016 deferred seam
"auditing the collector's own control-socket writes into a signed chain."

## Context

bulkhead's audit story is "every authority change is on an Ed25519-signed, hash-chained,
domain-tagged, tamper-evident log." Two chains carried it: the collector's kernel-verdict chain
(`/data/bulkhead/audit/provenance.jsonl`, domain `collector`, written single-writer by the ringbuf
loop) and the broker's gated-decision chain (`/data/bulkhead/audit-broker/provenance.jsonl`, domain
`broker`). A boot gate (`bulkhead-verify-audit.service`) re-verifies both against the sealed seed
before the signers append, so a forged/tampered chain refuses the boot.

ADR-0016 introduced a THIRD class of authority change that landed OUTSIDE that story: the collector
control socket now performs the `bpf()` WRITES that non-TCB callers can no longer make themselves —
a jailed agent's per-instance egress manifest (`EGRESS-SET-SELF`/`CLEAR`/`GRANT-CLEAR-SELF`), the
broker's TCB membership (`TCB-REGISTER-BROKER`), and the enforce master switch
(`ENFORCE-SET`, ADR-0016 review). These were only `log.Printf`'d, not signed. So who got which
egress manifest, who became TCB, and when E0/E2 was armed or disarmed left no tamper-evident trace
— a real audit-completeness gap, and exactly the kind of thing that becomes load-bearing the moment
a box boots hardened (ADR-0016's next step). `control.go` had zero audit appends.

## Decision

Sign the control-socket authority writes onto a SEPARATE, third audit chain.

1. **A `control` chain, not the collector chain.** The collector now writes two chains: the
   existing single-writer kernel-verdict chain (the ringbuf loop) and a new
   `/data/bulkhead/audit/control.jsonl` (domain `control`) for the control-socket writes. A
   separate chain — rather than folding control records into the kernel-verdict chain — keeps the
   hot ringbuf path single-writer and untouched (folding would make it multi-writer, needing a lock
   on every kernel event), and lets the boot gate verify each independently. Both chains live in
   the collector's audit dir and are signed with the SAME sealed seed (ADR-0008); the per-chain
   DOMAIN tag (ADR-0013 F4) bound into the signed hash keeps a record of one chain from verifying
   as a record of another, so the shared seed is not a cross-chain transplant vector.

2. **`recordControl` reuses the existing substrate.** A `recordControl(hook, comm, decision, mode,
   cgid)` helper appends a `provEvent` (overloaded exactly as the broker's `recordDecision` does):
   `hook` = the verb (`control:egress-set` / `control:egress-clear` / `control:grant-clear` /
   `control:tcb-register-broker` / `control:enforce-set`), `cgroup` = the affected (kernel-attested
   self / broker / 0) cgid, `decision` = `ok|err`, `mode` = the applied detail (the classes,
   `registered`, `bpf=1`, …). No new signing/canonical/verify code — `openAuditLog` gains a
   filename parameter so the collector can open `control.jsonl` beside `provenance.jsonl`.

3. **Serialized appends.** Control handlers run concurrently (goroutine-per-conn from the accept
   loop), and `auditLog.append` is not internally locked (the broker gets away with it only via its
   single blocking approval gate). Every control WRITE verb already holds `controlMu` across its map
   Update; the `recordControl` append happens inside that same critical section, so the control
   chain's seq/prev-hash/file writes are serialized. The control chain is opened in `runCollector`
   BEFORE the control accept loop starts, so no write is ever served unsigned.

4. **What is and isn't recorded.** Every POST-AUTH authority change is recorded (applied =>
   `decision=ok`; a map write that fails => `decision=err`) — the tamper-evident log of what
   actually changed. AUTH REJECTIONS (a non-agent self-verb, a non-broker register, a non-operator
   enforce toggle) are NOT chained: they changed no authority, and the 0660-root socket is not
   agent-reachable, so a rejected attempt is a misconfigured-/compromised-root event that is
   `log.Printf`'d, not signed (chaining them would let a root spammer bloat the chain for no
   authority delta).

5. **Boot gate.** `bulkhead-verify-audit.service` gains a third `verify-audit
   /data/bulkhead/audit/control.jsonl` line; a missing file (no control writes yet) verifies as OK
   (`verifyChain` returns `(0, nil)` for `IsNotExist`), so first boot is unaffected and a
   tampered/forged control chain refuses the boot exactly as the other two do. `chainDomain` maps
   the `control.jsonl` filename to the `control` domain.

## Verification

Host `go test` (src/collector): `TestControlChainDomain` — a control-domain record verifies under
`control` and is REJECTED under `collector`/`broker` (the F4 transplant protection extends to the
new chain), and `chainDomain()` maps `control.jsonl`→`control`, `provenance.jsonl`→`collector`,
`audit-broker/...`→`broker`. All existing audit suites (`TestVerifyChainRoundTrip`, tamper,
subchain-deletion, wrong-domain) stay green — the canonical/verify code is untouched.

QEMU (`scripts/qemu-agent-orch-check.py`, the ARM AUDIT/SIGN arm): after a real orchestration run,
all THREE signed chains `verify-audit` OK, and the `control.jsonl` chain RECORDS the broker's
`control:tcb-register-broker` and every agent's `control:egress-set` — proving the control-socket
authority writes are now tamper-evident, not just logged.

## Seam

DEFERRED: off-box anchoring of the control chain's head for tail-truncation detection (carried
forward from ADR-0013 F5b, unchanged by this slice — a tail-truncation of the newest records is
detectable only against an off-box anchor); correlating an `enforce-set` disarm to an operator
identity beyond uid-0 (the control socket attests uid==0 + non-agent, not WHICH operator — the
broker's approve.sock SO_PEERCRED already carries pid, a future enrichment). Folding the broker's
own EXPAND/NARROW/GRANT writes onto the control chain is NOT needed — the broker already signs them
on its own chain.
