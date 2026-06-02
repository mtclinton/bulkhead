# ADR-0010: Operator-initiated egress NARROW (in-place incident throttle)

Status: Accepted
Date: 2026-06-02
Relates to: ADR-0009 (generalized approval-gate + operator-approved egress EXPAND —
this is its operator-initiated dual), ADR-0007 (the human approval-gate + the uid-0
operator channel), ADR-0006 (delegation), ADR-0004 (E2 egress manifest).

## Context

ADR-0009 added EXPAND: a running agent asks to *widen* its own egress manifest, granted
only on human approval (agent -> human, gated). This ADR adds its operator-initiated
dual — **operator-initiated NARROW**: an operator (uid-0, the existing authority) clamps
a NAMED, running agent's egress manifest to `live &^ classes` **immediately, in place,
without killing the agent**. The use case is incident response: throttle a misbehaving
agent's egress now, without tearing down its process. Where EXPAND is agent->human
(gated), NARROW is human->agent, so the request->approve block is removed, not mirrored.

## Decision

**Operator-direct, NOT gated.** The approval gate (ADR-0007) exists to interpose a HUMAN
operator between an UNTRUSTED agent request and a privileged side effect. NARROW's
initiator IS that operator (uid-0, attested by `SO_PEERCRED` on `approve.sock`). Routing
it through `register`/`approve`/`resolve`/`finishGated` would ask the operator to approve
their own action — ceremony with no security gain — and would add a 120s timeout window
during which the misbehaving agent keeps its egress, defeating the whole point. So NARROW
**skips the `pend` registry entirely**: it runs synchronously inside `handleApprove` after
the `uid==0` check. It still re-verifies identity (`reverifyCgroup`) and still appends one
signed record to the broker decision chain.

**Wire surface.** One new verb on the EXISTING `approve.sock`: `NARROW <target> <classes>`,
handled in `handleApprove`'s switch beside `LIST`/`ALLOW`/`DENY`. New operator CLI
`bulkhead-collector narrow <target> <classes>`. The socket is already `0600 root` +
`SO_PEERCRED uid==0`, so authz is inherited verbatim (a non-root `DynamicUser` agent gets
`EACCES` at connect, then `uid!=0`). The agent-facing `broker.sock` has NO `NARROW` case,
so an agent cannot even name the action — it cannot narrow itself or a sibling.

**Arithmetic — clamp-bits-only, no ceiling.** `narrowMask(cur, req) = cur &^ req`, the
exact complement of `expandMask`. Requesting a class the agent lacks is a no-op on that
class. A ceiling is meaningless for a monotone-decreasing op and is omitted. `final == live`
=> write nothing, reply `OK … (no-op)`, but still record the decision.

**Target naming.** `<inst>` or `bulkhead-agent@<inst>.service` (instance tail validated by
`validInstance` — the `validSuffix` charset `[a-z0-9-_]` so no traversal, but a 64-char cap
so broker-minted child instances `d-<hex>-<suffix>` stay addressable) or an explicit
`/sys/fs/cgroup/bulkhead-agent.slice/…` path. `id:N` is **refused** — a bare id cannot be
checked against the agent slice. A new `resolveAgentTarget` builds the canonical path,
resolves it via `cgroupIDFromInode`, and **requires the path to contain
`/bulkhead-agent.slice/bulkhead-agent@`** (the same predicate `handleBrokerConn` uses) so
the collector, broker, PID-1/root, and the operator's own `session.scope` can never be
clamped.

**Unrestricted (no manifest) => refuse (`ERR no-manifest`).** There is no `cur` to subtract
from; *creating* an entry would clamp the agent to exactly the named-complement (every
unset class flips to deny once E2 bites) — a create-surprise that changes the verb's
contract. Symmetric to EXPAND's `ERR no-manifest`. The operator who genuinely wants to
clamp a wide-open agent uses the existing `egress set <target> <complement>`.

## Verification

**execute-time discipline (reused).** `reverifyCgroup(cgPath, cgID)` re-stats the path
immediately before the write and demands the live inode id still equals the resolved id;
`ebpf.UpdateExist` refuses to CREATE on a recycled/cleared key. The only value trusted to
drive the write is the live-re-derived one; the operator's typed name is advisory. Because
identify+reverify+write run back-to-back under `egressMu` with no human gap, the recycle
window is sub-millisecond, but the discipline is applied anyway (uniform with EXPAND).

**Concurrency.** A new dedicated `egressMu` serializes ALL broker `egress_policy`
read-modify-writes. NARROW takes it; EXPAND's `execute()` is amended to take it too (it
currently takes none — only DELEGATE took `launchMu`). Both re-read the LIVE mask under the
lock and recompute, so a NARROW racing an approved EXPAND on the same cgroup composes
deterministically by lock-acquisition order with no lost update and no torn mask. `egressMu`
is distinct from `launchMu` (no coupling to `launchChild`'s `systemctl` section) and NARROW
never touches `pendMu` (no lock-order inversion, no deadlock against a parked EXPAND
goroutine).

**Audit (F4).** One signed record on the broker's OWN chain, AFTER the write: `CgroupID` =
the re-verified target cgID, `Comm` = truncated instance tag, `Hook` = `narrow-egress`,
`Decision` = `narrow`|`narrow-noop`|`error`, `Mode` = `<operator uid:pid> req=<classes>
applied=<final>`. Written on EVERY outcome; reflects actually-applied state. The collector's
single-writer provenance chain is never touched.

Host `go test -race`: `TestNarrowComputesMask` (clears requested bits, never sets one, no-op
on absent classes), `TestResolveAgentTargetRejectsNonAgent` (non-slice path / `id:N` /
bad-charset refused), reuse `TestReverifyCgroupRebindsIdentity`.

qemu (`scripts/qemu-narrow-check.py`, same console-operator/poweroff shape as the EXPAND
demo, E2 armed FIRST so the manifest bites), arms: **(1) clamp** — agent `narrowee`
(`loopback,private,public`) probes private (succeeds), operator `narrow narrowee
private,public` -> the agent's *second* probe to private is DENIED (rc=7) while loopback
still works and the agent process is still alive; **(2) no-op** — `narrow narrowee
linklocal` -> `OK … (no-op)`, unchanged; **(3) unrestricted-refuse** — `ERR no-manifest`,
nothing created; **(4) non-agent-refuse** — a `/system.slice/…` path or `id:N` -> `ERR
not-an-agent`, collector untouched; **(5) agent-cannot-narrow** — an agent reaching
`approve.sock` gets `EACCES`. Plus: a signed `narrow-egress` record and `verify-audit`
still passes.

**Honest scope:** this proves the **E2 class gate flipped allowed->denied for ONE named
cgroup via an operator command** (the dual of ADR-0009's denied->allowed) — not a kill.
NARROW gates FUTURE `connect()`s (E2 hooks `socket_connect`); an already-ESTABLISHED socket
survives until it closes. For a hard stop the operator still `systemctl stop`s the instance.
The clamp is live map state: a restart re-applies the agent's configured manifest via
`+ExecStartPre egress set self`, so to make it stick the operator edits the instance
drop-in. No new BPF/map; the verified E0-E3 object is byte-for-byte unchanged; no new
systemd unit.

## Seam left clean

Narrow is operator-direct via `recordDecision`/`recordNarrow`; it deliberately does NOT
flow through `finishGated` (the operator IS the gate). The kernel-enforced one-shot E1/E3
privilege grant (ADR-0009's "concrete next") remains the next gated action and is NOT built
here. Deferred (inherited): persistent pending/decisions across broker restart, a dedicated
broker record type instead of overloading `provEvent`, a per-agent ceiling map, the tailnet
operator transport, and a future safe re-admission of the `id:N` target form (via a slice
walk that maps id->path so the agent-slice predicate stays checkable).