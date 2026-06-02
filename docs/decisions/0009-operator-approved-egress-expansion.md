# ADR-0009: Generalized approval-gate + operator-approved egress expansion

Status: Accepted
Date: 2026-06-01
Relates to: ADR-0007 (the human approval-gate — this fills its "generalize beyond
delegation" seam), ADR-0006 (delegation), ADR-0004 (E2 egress manifest).

## Context

ADR-0007's approval-gate was wired only to delegation. The broker's gate (register →
block-for-operator → resolve, the uid-0 control socket, the signed decision chain) is a
general primitive; this ADR (1) generalizes it to arbitrary sensitive actions and (2) adds
the first new action — **operator-approved egress expansion**: a running agent asks to
*widen* its own egress manifest, granted only on human approval. It is the dual of
delegation: delegation *narrows* for a child (`parent ∩ requested`); expansion *widens* for
self — and widening is a privileged op an agent cannot do itself (it cannot `bpf()`), so it
requires the TCB broker + a human. The canonical "an agent asking for MORE access needs a
human" primitive.

## Decision

**Generic action model (minimal).** `pending` gains a `kind actionKind` and an
`execute func(*pending) (string, error)` closure. The gate — `register`/`approve`/`resolve`/
`handleApprove`/`listPending`/`recordDecision`/the signed chain/the uid-0 socket — is
action-agnostic; each kind's handler peer-attests the requester, builds a
`pending{kind, …, execute: closure}`, and calls the shared `finishGated`, which runs the
gate and (ONLY on approve) `p.execute`. Delegation is refactored onto this with no behavior
change. No interface ceremony — the closure captures per-action params. The kernel-attested
requester cgroup keeps the field name `parentCgID` (parent for delegate, self for expand) so
the flood accounting and tests are untouched.

**Expansion (`EXPAND <classes>` on the existing broker socket).**
- The target cgroup is the **kernel-attested SELF** (`peerParentCgID`, SO_PEERPIDFD). The
  request body carries NO identity, so an agent can only ever widen *itself*, never another.
- `newMask = current | (requested ∩ ceiling)`. The map write happens in `execute()` — only
  after approval — which **re-reads the LIVE mask and uses `ebpf.UpdateExist`**: if the
  agent exited and its `ExecStopPost` cleared the entry (cgroup id possibly recycled onto a
  different agent) between request and approval, the write is refused (`ENOENT`) rather than
  resurrecting/granting a manifest on a stale/reused cgroup. Closes the request→approval
  TOCTOU on the cgroup lifecycle.
- **Unrestricted (no current manifest) ⇒ refuse** (`ERR no-manifest`): there is nothing to
  widen, and *creating* an entry would NARROW an unrestricted agent (every unset class
  becomes a deny once E2 bites). Symmetric to delegation's `ERR no-parent-manifest`.
- **No-op short-circuit** before registering: if no new grantable bit is added, reply
  `OK … (no-op)` (already held) or `ERR above-ceiling` (asked for classes all clamped by
  the ceiling) — don't burn an operator decision or let an agent flood the queue.

**Ceiling (`BULKHEAD_EXPAND_CEILING`).** ONE hard per-deployment cap an EXPAND can never
exceed even with approval (defense-in-depth). Default = all DST_* classes (the operator is
sole authority out of the box); a deployment clamps it (e.g. never let any agent reach
`public` regardless of approval). Parsed once at startup, fail-closed on a bad value.

**Invariants preserved (all from ADR-0006/0007, unchanged):** no self-approval (the uid-0
`0600 approve.sock` — agents are non-root DynamicUser; `handleApprove`/`resolve`/the socket
are untouched); the map write is reached ONLY after `<-decision == true` (deny/timeout/flood
→ `ERR`, no write); the broker's `Update` rides its existing CAP_BPF + `tcb_cgroups`
self-registration (E0/E2-safe). New client verb `bulkhead-collector expand <classes>`.

No new BPF/map; the verified E0–E3 object is unchanged.

## Verification

Host `go test -race`: `TestExpandComputesMask` (the widen arithmetic: clamp to ceiling,
never drop a held class), `TestGateActionAgnostic` (the gate delivers exactly-once for a
non-delegate kind), and the existing approval/delegation tests still pass.

qemu (same console-operator shape as ADR-0007), four arms, E2 armed first:
1. **allow** — agent `expander` (manifest `loopback,other`) probes public (denied, rc=7),
   requests `expand public`, operator `approve allow <id>` → broker re-reads + `UpdateExist`
   widens its manifest → the agent's *second* probe to the same cgroup succeeds (rc≠7). The
   `approve list` row reads `action=expand-egress agent=… current=loopback,other
   requested=public grant=loopback,other,public`.
2. **deny** — `approve deny` → `ERR deny`, manifest unchanged, public still denied.
3. **timeout** — operator does nothing → `ERR timeout`, no change.
4. **agent-approve rejected** — an agent connecting to `approve.sock` gets EACCES.
Plus: the broker's signed chain has an `expand-egress` decision record.

**Honest scope:** this proves the **E2 `public` class gate flipped denied→allowed for one
cgroup via operator approval** — not "the internet became reachable." `api.anthropic.com` is
reachable only because it is floor-allowlisted (dnsmasq→nftset); the nftables host floor
still gates *which* IPs. E2 must be armed or the before-probe wouldn't be denied (the test
would be vacuous).

## Seam left clean

Any future gated action = a new `actionKind` + a handler that peer-attests, builds a
`pending{kind, …, execute}`, and calls `finishGated`; add a `case` to `listPending`/
`recordDecision`. Concrete next: one-shot E1/E3 privilege grants, operator-initiated NARROW
(`current &^ classes`), model/route switches. Deferred (from ADR-0007): persistent pending
across restart, a dedicated broker record type, a per-agent ceiling map, the tailnet
operator transport.
