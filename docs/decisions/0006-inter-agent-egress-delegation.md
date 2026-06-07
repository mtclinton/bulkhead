# ADR-0006: Inter-agent egress delegation (narrow-never-widen)

Status: Accepted
Date: 2026-05-31
Relates to: ADR-0004 (E2 per-agent egress), ADR-0005 (agent jail runner), ADR-0001
(deferred: inter-agent capability delegation)
Superseded-in-part (roadmap, Proposed): [ADR-0034](0034-egress-structural.md) reclasses the
dnsmasq→nftset domain allowlist as advisory, not the egress boundary. NB the monotone-attenuating
*delegation* model here (parent ∩ requested) is NOT superseded — [ADR-0037](0037-multi-agent-domains.md)
builds its cross-domain authority model on it. Roadmap; the shipped allowlist remains in force until
the ADR-0034 proxy ships.

## Context

ADR-0005 gives each agent its own cgroup and an egress-class manifest set at launch. The
next multi-agent slice: let a PARENT agent spawn a CHILD with a *subset* of the parent's
egress. The parent is untrusted — jailed, non-root, no caps, and (by the floor's
`bpf()`-EPERM seccomp) physically unable to write the BPF `egress_policy` map. So a
privileged **TCB broker** must mediate, and the only safe rule is **narrow-never-widen**:
a child may never reach a destination class the parent cannot.

## Decision

A `bulkhead-collector broker` listener (socket-activated by `bulkhead-broker.socket` on
`/run/bulkhead/broker.sock`) plus a `bulkhead-collector delegate` client the parent runs
inside its jail. One request line: `DELEGATE <child-suffix> <requested-classes>`. The
broker:

1. **Attests the parent from the kernel — never from the request.** It gets a pidfd via
   `SO_PEERPIDFD` (captured at `connect()` time, bound to the connecting task's
   `struct pid`), reads the authoritative pid from the pidfd's `fdinfo`, then reads
   `/proc/<pid>/cgroup`. Because the pidfd pins the pid *number* against recycle while
   held, there is no connect→read TOCTOU: the cgroup read is the original task's. A
   liveness recheck (`PidfdSendSignal(pidfd, 0)`) fails closed if the task died. The
   request body carries **no identity** — nothing for a parent to forge. The parent
   cgroup must be under `/bulkhead-agent.slice/bulkhead-agent@` (only a real agent may
   delegate).

2. **Reads the parent's CURRENT ceiling from the live pinned map.** `Lookup(parentCgID)`
   on `egress_policy` — the same map the BPF program enforces against. A miss ⇒ the
   parent has no manifest ⇒ **may not delegate** (you cannot safely subset
   "unrestricted"). No stale snapshot, no env/config read, is ever consulted.

3. **Intersects.** `childMask = parentMask & requestedMask`. A bare bitwise AND can only
   *clear* bits — widening is arithmetically impossible. There is no "check + error"
   branch (a place to get the polarity wrong); just the AND.

4. **Launches the child as a normal jail instance**, reusing ADR-0005's proven ordering.
   It writes a transient `/run/systemd/system/bulkhead-agent@<inst>.service.d/` drop-in
   carrying `BULKHEAD_AGENT_EGRESS=<classNames(childMask)>`, `daemon-reload`s, then
   `systemctl start`s the instance. The child's own `+ExecStartPre` writes
   `egress_policy[childCgID]` in the child's cgroup *before* the payload forks — the
   child cannot `connect()` before its (narrowed) manifest exists. The instance name is
   broker-minted `d-<8hexrand>-<suffix>` (the parent's suffix is cosmetic, validated
   `^[a-z0-9_-]{1,24}$`) so a parent cannot collide with or hijack a sibling instance.

Every edge fails closed (bad suffix / map miss / parse error / drop-in write /
`daemon-reload` / `start` / child `+ExecStartPre` non-zero → `ERR`, no child runs
unrestricted). `ExecStopPost=-+… egress clear self` (already in the template) drops the
child's map entry on exit.

**Broker trust.** Runs in `system.slice`, `User=root`, `AmbientCapabilities=CAP_BPF`
(only — the maps are already created/pinned by the collector; it just `Lookup`/`Update`s
them), `RestrictAddressFamilies=AF_UNIX` (it never makes outbound connections),
`ProtectSystem=strict` + `ReadWritePaths=/run/systemd/system`. On startup it
**self-registers its own cgroup into `tcb_cgroups`** so its `bpf()` map ops survive E0
(`lsm/bpf` deny) and its IPC is E2-exempt — the one detail that makes a TCB map-reader
work under enforcement. `SocketMode=0666` is safe because authorization is *purely* the
kernel-attested peer cgroup; a non-agent connector is rejected at step 1.

No new BPF program, no new map, no change to the verified E0–E3 object: delegation only
changes *who computes the egress value* (the broker, via intersection) — the enforcement
and the launch-ordering are unchanged.

### Why not have the broker write the child's map entry directly?

That would need the child cgroup id *before* the cgroup exists, re-introducing a
launch/write race. ADR-0005's in-unit `+ExecStartPre` already closed it; reuse it.

### Limitation: E0 + delegation

The child's `+ExecStartPre` `bpf()` runs in the child's *non-TCB* cgroup; with E0
(`enforce on bpf`) armed it would be EPERM'd — exactly ADR-0005's documented limitation.
Likewise the broker's startup self-register needs E0 *off* at first run. This MVP targets
**E2** with E0 at its default (off), so both are correct and shippable today. The
E0+delegation path (broker writes the child entry from its own TCB context, ordered
`Before=` the payload) is a stated seam, not built.

## Verification

Headless qemu, two demo parents, same broker code path, opposite child verdict:

- **parentP** manifest `loopback,other` (NO public) delegates a child *requesting*
  `public,loopback,other`. Broker reads P's ceiling = `loopback|other`, intersects →
  `loopback|other` (public bit cleared). The child's public probe is **DENIED**
  (`curl` exit 7 == `connect()` EPERM): **the parent could not widen.**
- **parentQ** manifest `public,loopback,other` delegates the same request → intersection
  keeps `public`; the child **reaches** the public internet (rc≠7).

Both children reach loopback (class precision). The probe target `api.anthropic.com` is
allowed by the nftables floor (dnsmasq nftset), so the child-P denial is purely the BPF
E2 manifest. The signed audit log carries a `socket_connect`/denied/enforce record on
child-P's public connect and an allowed one on child-Q's — opposite verdicts, different
cgroups, same hook, from delegated children. Verified live, all checks pass.

## Seam: human approval-gate (next slice, NOT built)

`cmdBroker` has one synchronous, fail-closed insertion point — `approveDelegation()`,
after computing `childMask`, before launch. The MVP stub returns `true`; the next slice
makes it block on operator ack over the tailnet and return `false` on denial/timeout —
same reply path, and (unlike an in-unit `ExecCondition`) **no child cgroup is created on
denial**. The Ed25519 hash-chained provenance log is the audit substrate; the broker may
append a `delegate` decision record via the existing `auditLog.append` path. Neither
touches the BPF object, the maps, or the E0–E3 verdict logic.
