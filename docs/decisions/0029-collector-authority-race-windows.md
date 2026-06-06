# ADR-0029: closing two race windows on the collector authority surface

Status: Accepted
Date: 2026-06-06
Relates to: ADR-0016 (the collector control socket — the bpf()-WRITE chokepoint), ADR-0018
(harden-by-default + the boot race: the collector is `Type=exec` and binds the control socket as its
LAST startup step), ADR-0005 (fail-closed: an agent +ExecStartPre that cannot get its egress manifest
must fail the unit, not fork the payload), ADR-0012 (TCB-context GC — the delete-only, full-recompute
reclaim of per-agent map entries), ADR-0011 (one-shot privilege grant), ADR-0024 (the `controlMu`
atomicity invariant). Retroactively documents commits `52f9ab9` and `dbda009`, which shipped as fixes
without their own decision record. Closes both items left OPEN as design judgment-calls after the
2026-06-06 security-audit hardening loop.

## Context

The collector is the single bpf-map writer and the one always-on TCB process, so every authority change
(grant a hook, set/clear an egress manifest, register the broker into the TCB set, prune a dead agent's
entries) funnels through it. Two of those paths had a race window. Both were CONFIRMED real by the audit
loop and both were deliberately NOT auto-fixed, because the obvious one-line fix to each would have
traded away a fail-closed / least-privilege property to buy correctness. They are recorded together
because the design tension is identical: **close the window without weakening the invariant the window
sits inside.**

1. **Control-socket boot race (a LIVENESS gap that the naive fix closes by weakening fail-closed).**
   `cmdControl` (the `bulkhead-collector ctl …` client run by the agent's +ExecStartPre, the broker, and
   the enforce-arm gate) polled on a non-OK reply ONLY for `wait-broker-tcb`; every other verb was
   one-shot. But the agent unit is ordered only `After=bulkhead-collector.service`, which does NOT
   guarantee the socket is bound — the collector is `Type=exec` (active at execve) and binds
   `/run/bulkhead/control.sock` as its last startup step (after the BPF load/attach/pin + audit opens,
   ADR-0018). So a cold-boot `egress-set-self` could dial before the socket existed, get an immediate
   ENOENT, and fail the agent unit — a real boot race, the same one `wait-broker-tcb` and the broker's
   `TCB-REGISTER-BROKER` already polled through. The surfaced one-liner ("make `time.Now().After(deadline)`
   the only exit so ALL verbs poll") would close it — but it would also retry GENUINE server rejections
   (`ERR not-an-agent`, `ERR bad-classes`) for the full 30s window, masking a real fail-closed rejection
   behind a timeout instead of failing fast. The judgment call: is the one-shot deliberate fail-closed, or
   an oversight ADR-0018 should have covered? Answer: an oversight — but the fix must keep rejections fast.

2. **GC delete/writer race — "BH-001" (a SAFETY gap; high-filed, but overstated).** `gcLoop`
   (ADR-0012) scans the live agent-slice cgroups lock-free (`liveAgentCgids()`, deliberately outside
   `controlMu` for latency, ADR-0024) and only THEN takes `controlMu` to delete per-agent map entries
   whose cgid is absent from that set. An agent created between the scan and the lock — whose
   `handleBrokerConn` writes a fresh, operator-approved `grant_once` — is absent from the stale `live`
   set, so the racing pass could reap its authority: a silent revocation of an authorized op. `egress_policy`
   was ALREADY immune (it carries a two-pass `seen` witnessed-live guard: prune a dead cgid only if a prior
   pass saw it live), but `grant_once` had no such guard. Fully closing it by recomputing `live` under
   `controlMu` would block control writes during the (deliberately lock-free) cgroup scan; and `grant_once`
   is written under a DIFFERENT lock (`grantMu`, in the broker process), so a lock-discipline change across
   `controlMu`/`grantMu`/`egressMu` is the heavy hammer. The judgment call was the severity and the shape
   of the fix.

## Decision

**Each window is closed by reusing a discipline already present elsewhere in the same file — no new lock,
no new map, no ABI change.**

1. **Control socket — classify the reply, don't blanket-retry.** A pure
   `shouldRetryControl(verb, resp)` (`control.go`) drives `cmdControl`'s loop:
   - A **transport failure** — `controlRPC` wraps dial/send/read errors with a `"control "` prefix — means
     the socket is not yet bound. Retry it for EVERY verb (the boot race). This is the same `"control "`
     transport-vs-server split `controlRPCGate` (ADR-0021) already uses for the posture gate.
   - A **server reply** (`"ERR …"`, no `"control "` prefix) is a real rejection and is TERMINAL for the
     one-shot verbs — so `egress-set-self` fail-closes IMMEDIATELY (non-OK exit fails the unit, the payload
     never forks, ADR-0005 preserved) instead of hiding the rejection behind the 30s window.
   - `wait-broker-tcb` is the sole verb that also polls on a server reply: its expected `ERR not-registered`
     IS its poll loop while the broker self-registers.
   `brokerRegisterTCB` and the enforce-arm (`main.go`), which use `controlRPCRetry` (retry-on-any), are
   UNCHANGED: every server `ERR` they can receive at boot is either impossible-for-them (`not-broker` for
   the broker itself) or transient (`map`/`broker-cgroup` not ready), so retry-on-any is already correct.

2. **GC grant_once — give `gcLoop` the witnessed-live guard egress already has.** `selectGrantPrunes`
   takes a persistent `grantSeen` set (`gc.go`): a dead cgid is reaped only if a PRIOR pass witnessed it
   live. A grant written during the scan→lock window (never witnessed) is SPARED on the racing pass and
   reaped on a later one once its agent is genuinely gone. `cmdGC` passes a `nil` grantSeen → it keeps its
   documented authoritative single-pass (it is a one-shot CLI, never concurrent with the loop). This is
   `gc.go`-only; the deliberate lock-free scan stays lock-free, and the E0-E3 BPF object is byte-for-byte
   unchanged.

## Verification

- **Control socket:** `TestShouldRetryControl` asserts every verb retries the three transport-failure
  forms; the one-shot verbs treat every server `ERR` as terminal; `wait-broker-tcb` keeps polling on
  server replies. `go build/vet/test -count=1` + `CGO_ENABLED=1 go test -race` green; Go CI green.
- **GC:** `TestSelectGrantPrunesRaceGuard` walks the three-pass story — a never-witnessed dead grant is
  spared, a witnessed-live one is recorded, a witnessed-then-dead one is reaped; the `nil`-grantSeen
  (`cmdGC`) authoritative single-pass is covered by the existing `TestSelectGrantPrunes`. Same race-clean
  test gate.
- **Live:** the egress-set-self path the control fix changes is the exact +ExecStartPre control-socket
  grant flow `scripts/qemu-e0-check.py` drives on a cold boot; a green `verify-e0` on the re-pinned image
  is what confirms the fix behaves against real systemd ordering, not just in the unit test.

## Honest severity note

BH-001 was filed "high" but is practically unreachable in production: `egress_policy` was already guarded,
and the grant window is the sub-millisecond gap between a lock-free `stat` scan and the `controlMu`
acquire on the very next statements. It is closed here for symmetry and correctness, not because it was
exploitable. The control-socket race, by contrast, is a genuine cold-boot failure that would fail an
agent unit — the more operationally significant of the two.

## Seam

- **`controlRPCRetry` could adopt the same transport-vs-server classification** so that a persistent
  server rejection to the broker/enforce-arm also fails fast rather than burning the 30s deadline. Left
  alone deliberately: their reachable server `ERR`s are all impossible-or-transient today, so the change
  would be speculative. Revisit if a new verb gives those callers a fast-rejectable server error.
- **A structural agent-born tag for grant_once** (an ADR-0012 seam) would let the GC reclassify a grant
  cgid as ex-agent without the witnessed-live ratchet, making `cmdGC` restart-robust for grants too. It
  needs a companion pinned set / map change, deliberately avoided here.
