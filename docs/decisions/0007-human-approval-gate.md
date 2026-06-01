# ADR-0007: Human approval-gate for inter-agent delegation

Status: Accepted
Date: 2026-05-31
Relates to: ADR-0006 (delegation broker; this fills its `approveDelegation` seam),
ADR-0001 (deferred: human-in-the-loop approval gate for sensitive actions)

## Context

ADR-0006's broker computes `child = parent ∩ requested` and launches the child via a
single synchronous, fail-closed insertion point — `approveDelegation()`, a stub that
always returned `true`. This ADR makes it block for a **human operator** decision before
any child is created: approve → launch; deny / timeout → `ERR`, no child.

## Decision

**Concurrency.** The broker's accept loop was serialized (`handleDelegate` called
inline). A blocked approval there could never accept the operator's decision — a
self-deadlock. Fix: **two independent accept loops** (delegation socket + a new control
socket) with **goroutine-per-connection**, and an in-memory pending registry guarded by
one `sync.Mutex`. A parked delegation goroutine holds no lock while waiting.

**Block-until-decision (synchronous).** Keeps the existing one-request/one-reply
protocol and ADR-0005/0006 launch-ordering; no ticket store or poll verb where a child
could leak. `approveDelegation(p)` registers the pending, arms a `time.AfterFunc(timeout)`,
and blocks on `<-p.decision`. Both the operator decision and the timeout funnel through
**one resolver** (`resolve`) that deletes the registry entry under the mutex and then
sends on a cap-1 channel — so the verdict is delivered **exactly once**; whichever of
operator-vs-timeout deletes first wins, the loser is a no-op. No `select`-random-pick
race, no double-launch (launch is strictly after `<-p.decision == true`).

**Timeouts.** Broker `approvalTimeout` = 120s default (`BULKHEAD_APPROVAL_TIMEOUT`,
seconds); timeout ⇒ **deny**. The `cmdDelegate` client deadline is raised to 180s
default (`BULKHEAD_DELEGATE_TIMEOUT`), strictly **greater** than the broker timeout, so
the broker's definite `OK`/`ERR` always lands before the client gives up — no orphaned
state, no ambiguous parent `rc`. The demo uses 8s / 20s (same inequality).

**Operator channel + auth.** A second AF_UNIX listener the broker creates in-process at
`/run/bulkhead/approve.sock`, `chmod 0600` (root-only). `handleApprove` additionally
checks the peer is **`uid == 0`** via `SO_PEERCRED`. The operator CLI is
`bulkhead-collector approve list|allow <id>|deny <id>`.

> **Why `uid==0` and NOT a TCB-cgroup check** (the key correctness fix vs the naive
> design): a root login or `tailscale ssh root@` lands in a `session-N.scope` under
> `user.slice`, which is **not** in `tcb_cgroups` (only the collector and broker
> self-register *their own* cgroups). A TCB-cgroup gate would false-reject the only
> legitimate operator. `uid==0` is the unforgeable operator identity here. The
> TCB-cgroup check stays where it belongs — the *agent-attestation* direction
> (`peerParentCgID`), unchanged.

**Why an agent can never approve — three independent denials:** (1) the socket is
`0600 root:root`; an agent is `DynamicUser` (non-root) → `connect()` is `EACCES`; (2)
even past that, `cred.Uid != 0` → `ERR not-operator`, and the jail (empty caps,
`NoNewPrivileges`, E3 setuid/capset deny) makes becoming uid 0 impossible; (3) the agent
slice's `IPAddressDeny=any` keeps any future tailnet transport unreachable from a jail.

**Transport vs auth.** The **auth** (uid-0 on a 0600 local socket) is built and is the
trust root. The **production transport** is designed, not built: flip
`tailscale-up.service` `--ssh=false → true` so a tailnet-ACL'd operator `ssh root@`
lands as uid 0 and runs the same CLI over the same socket (no broker network code); or a
small HTTP listener on `tailscale0` that authenticates via `tailscale whois` and proxies
onto the local socket. Either leaves the local-socket invariant — what's tested —
unchanged. In the demo the operator is the serial root console (same auth).

**Signed audit — separate chain.** The collector's Ed25519 hash chain is single-writer
(it owns `prevHash` in memory); a second appender would fork it. So the broker opens its
**own** chain by reusing `openAuditLog()`/`append()`/`canonical()` **verbatim** with a
distinct dir (`BULKHEAD_AUDIT_DIR=/var/lib/bulkhead/audit-broker`, → `/data/...` on
Yocto via a drop-in) and its own (ephemeral, TPM-sealable later) key. `canonical()` is
**untouched** — no re-encoding of the collector's verified chain. One record per
decision (no dangling pending), written before launch on approve and before the `ERR` on
deny/timeout, overloading `provEvent`'s six fields: cgroup = parent, comm = child
instance, hook = `delegate`, decision = `approve|deny|timeout`, mode = `<operator>
<req>-><grant>`.

**Flood backstop.** `register` rejects past `maxPending=64` total / `maxPendingPar=4`
per-parent-cgroup → `ERR busy` (fail-closed); a spamming agent can't exhaust
goroutines/fds or bury a real request. A broker restart drops all pending (fail-closed).

No new BPF/map; the verified E0–E3 object and the collector's chain are untouched.

## Verification

Host: `go test -race` proves `register`/`resolve` deliver exactly once and the
allow-vs-timeout race resolves deterministically over 200 iterations, plus the flood
caps (`broker_test.go`). qemu (pexpect-over-serial), four arms, all pass:

1. **pending → allow → child + egress proof.** parent delegates → blocks; `approve list`
   shows the pending row; `approve allow <id>` → child launches with the narrowed
   manifest and the E2 egress proof still holds (parentP, which lacks `public`, yields a
   child denied `public` — **the gate authorizes, it never widens**).
2. **deny → no child.** `approve deny <id>` → `ERR denied`; no child unit/cgroup; signed
   `"decision":"deny"`.
3. **timeout → no child.** operator does nothing → `ERR timeout`; no child; signed
   `"decision":"timeout"`.
4. **agent-approve → rejected.** an agent connecting to `approve.sock` gets `EACCES`
   (0600 vs non-root DynamicUser); any pending request is unaffected.

Plus: the broker's `decisions` chain has the signed records and the collector's
`provenance.jsonl` is unchanged (the two chains never crossed).

## Seams (documented, NOT built)

- **Generalize beyond delegation.** `approveDelegation(*pending)` is an instance of a
  generic `requestApproval(action)`: the registry, control socket, uid-0 auth,
  fail-closed timeout, and broker-owned chain are all action-agnostic. Wiring other
  sensitive actions (e.g. an agent requesting a privileged op) reuses the same machinery.
- **Production tailnet transport / UI** (SSH flip or HTTP-on-`tailscale0`) as above.
- **Persistent pending across broker restart** (currently in-memory, fail-closed) and a
  dedicated `brokerCanonical` instead of overloading `provEvent` string fields — trivial
  later refactors that don't touch the crypto.
- **E0 caveat** inherited from ADR-0006 (MVP targets E2; broker self-register needs E0
  off at first run).
