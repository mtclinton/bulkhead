# ADR-0033: io_uring: disable inside the sandbox, broker async I/O

Status: Accepted — the agent-side io_uring denial (per-sandbox seccomp) is SHIPPED + live-verified; the async-I/O broker and the default-tier (Sentry) enforcement point are pending
Date: 2026-06-07
Pillar: agent-isolation
Relates to: ADR-0031/0032 (substrate & interception whose observability this preserves), ADR-0034 (same broker-don't-expose pattern), ADR-0035 (brokered I/O rides the resource-auth layer).

## Implementation status

**Agent-side denial — SHIPPED + LIVE-VERIFIED (2026-06-09).** Both agent jail templates —
`bulkhead-agent@` (E2-gated) and the confined `bulkhead-agent-confined@` (ADR-0034 no-route
netns) — subtract `io_uring_setup io_uring_enter io_uring_register` from their
`SystemCallFilter`. This is load-bearing, not cosmetic: systemd's `@system-service` base
*allows* the io_uring family (it is a member of the `@aio` set), and there is no `@io_uring`
systemd set, so the three syscalls are denied by name. The confined egress probe asserts
`io_uring_setup` returns EPERM from inside the jail (the `IOURING` check, run by both
`make verify-egress-proxy` and `make verify-egress-reboot`).

Enforcement is **per-sandbox seccomp, deliberately not a global `kernel.io_uring_disabled`
kernel kill**: open question (2) below leaves room for the trusted broker to use io_uring
*internally* (gaining its performance while keeping rings out of the agent), which a system-wide
disable would foreclose. Denying at the sandbox boundary keeps that design space open.

**Pending:** the async-I/O **broker** that services agent I/O via discrete, observable syscalls
(the "broker, don't expose" half of the decision); and the **default-tier (Sentry) enforcement
point** (ADR-0031/0032), which is unbuilt — until the Sentry ships, the namespace-tier seccomp
denial above is the live control. The hostile-tier guest-kernel `io_uring`-off build is also a
later guest-image hardening item.

## Context and problem statement

bulkhead's isolation pillar rests on a separate-kernel boundary plus a tractable, *observable* syscall surface — the `sandprint`-style premise that what the agent does is mediated and watchable. io_uring breaks that premise at the structural level. By design it performs I/O through shared user/kernel ring buffers (SQ/CQ) rather than discrete syscalls, so once a ring exists, the tier's syscall mediator is structurally blind to the I/O issued through it [#6]: for the namespace/microVM tiers that mediator is host-side **seccomp, ptrace, and syscall-tracing EDR**; for the default tier it is the **gVisor-class Sentry's own syscall interception**, which likewise sees discrete syscalls, not shared rings. The ARMO "Curing" rootkit weaponizes exactly this blindness. io_uring also carries a heavy, *recurring* memory-safety history — UAF, ref-count over-put, race/double-free, including a 2026 zero-copy-receive wave — and is the verified basis for the widely-cited "~60% of kCTF kernel-exploit submissions" figure (a correct number, commonly mis-scoped) [#6]. The most security-conscious operators (Google/ChromeOS/Android) already disable or gate it [#6]. The question for bulkhead's observed/authorized agent tier: keep it, broker it, or ban it.

## Decision drivers

- **Observability is the product.** A primitive invisible to the tier's mediator — host seccomp/ptrace/EDR for the namespace/microVM tiers, the Sentry's own interception for the default tier — directly defeats the mediation and profiling the isolation pillar guarantees [#6].
- **Memory-safety attack surface.** A recurring kernel-CVE generator is the opposite of the bounded, enumerable surface the reimplement bet buys us (gVisor leaves io_uring only partial anyway) [#1][#6].
- **Compatibility cost is bounded.** Disabling io_uring is an enumerable gap, not an open-ended one — consistent with gVisor's existing partial support [#1].
- **Precedent.** Hardened platforms already chose to disable/gate it [#6].

## Considered options

- **Expose io_uring rings to the agent (rejected).** Maximizes async-I/O performance and compatibility, but creates a syscall-invisible I/O channel that nullifies seccomp/ptrace/EDR mediation and imports the full recurring kernel-memory-safety surface [#6]. Incompatible with the observability premise; non-negotiable rejection.
- **Restricted-opcode allowlist inside the sandbox (rejected as primary; kept as distant third).** Permit a curated subset of opcodes/registrations. Reduces but does not remove the structural blindness — any ring still moves I/O outside syscall tracing — and pushes correctness onto an opcode policy that the CVE record shows is a moving target [#6]. A distant third choice, not the boundary.
- **Disable io_uring inside the sandbox; broker async I/O through a trusted process (selected).** The agent gets no ring. Async I/O requests cross a mediated interface to a trusted broker that performs the work via observable syscalls and never hands a ring back. Preserves full seccomp/ptrace/EDR visibility and keeps the recurring io_uring surface out of the agent's reach, at a bounded compatibility cost [#1][#6].

## Decision

bulkhead WILL **disable io_uring inside the agent across BOTH the default (Sentry) and hostile (microVM) tiers** — the ban is not default-tier-only. In the default tier the agent will never hold an io_uring instance: `io_uring_setup` and ring registration are denied. In the hostile tier the agent's io_uring would be the *separate guest kernel's*, contained by the VM boundary but invisible to host mediation, so that guest kernel is built with io_uring disabled (a guest-image hardening item) — the broker-or-ban property holds there too. Async I/O WILL be **brokered through a trusted process** that services requests via discrete, observable syscalls and never exposes a ring to the agent. A restricted-opcode allowlist remains an explicitly disfavored fallback, used only where brokering is infeasible.

## Consequences

### Positive

- Restores complete syscall-level observability: no I/O path escapes the tier's mediator — the Sentry's interception (default tier) or host seccomp/ptrace/EDR (namespace/microVM tiers) [#6].
- Removes the recurring io_uring memory-safety surface from the agent's reach, shrinking the kernel attack surface in line with the reimplement strategy [#1][#6].
- Aligns bulkhead with the hardening choices of Google/ChromeOS/Android [#6].

### Negative / costs

- Loss of io_uring's batched/async performance for agent I/O; brokering adds an IPC hop and serialization overhead.
- Compatibility gap for software that hard-requires io_uring (consistent with gVisor's partial support) [#1]; the broker must cover the async patterns those workloads expect.
- New trusted component (the broker) to build, harden, and maintain.

### Residual risks the OS cannot touch

- **CVE floor, not census.** Report #6 flags its enumerated io_uring CVE list as a verified *floor* of 9, not a complete count — the true surface of the primitive (and of any opcode-allowlist fallback) is larger than enumerated [#6].
- **The broker is now the boundary.** Disabling rings in the agent does not eliminate io_uring from the host; a bug in the trusted broker, or in kernel io_uring code the broker itself touches, sits beneath this control [#6].
- **Side-channels and hypervisor/KVM 0-days** remain beneath every syscall-level boundary regardless of this decision [#10][#36].

## Confidence & open questions

High confidence on the structural rationale: the seccomp/ptrace/EDR blindness is a design property, not a bug, and the verification on report #6 was clean (32/32) [#6]. Open questions: (1) which async patterns the broker must expose to keep real agent workloads functional without re-importing ring semantics; (2) whether the broker should itself use io_uring internally (gaining performance while keeping it out of the agent) or stay on discrete syscalls for its own observability; (3) the precise enforcement point for the denial — Sentry-level vs. seccomp scalar pre-filter [#4].

## Evidence (source reports)

- [#6] io_uring: keep, broker, or ban — structural seccomp/ptrace/EDR blindness, ARMO "Curing" rootkit, recurring memory-safety history, the ~60% kCTF figure, Google/ChromeOS/Android gating, and the CVE-floor caveat.
- [#1] Syscall-interception sandbox architectures — reimplement collapses host surface; io_uring is only partially implemented; the gap is enumerable.
- [#4] Syscall-interception primitives — seccomp-notify as a scalar pre-filter; relevant to where the denial is enforced.
- [#10][#36] Side-channels and hypervisor/KVM 0-days beneath every boundary.

## Related ADRs

- **ADR-0031 / ADR-0032 (isolation substrate & interception primitive):** this decision presupposes the reimplemented-kernel (gVisor-class) boundary and Systrap-default interception, whose observability this preserves.
- **ADR-0034 (egress as a structural guarantee):** the same "broker, don't expose" pattern — mediated path through a trusted process, no direct route for the agent.
- **Open cross-cutting decision (the "mediation fabric"):** this async-I/O broker, the ADR-0034 egress proxy, and the ADR-0037 mediated-IPC channel are all trusted host-side mediators sitting in the post-compromise blast radius — exactly the surface ADR-0031 makes the primary TCB metric. Whether they are ONE hardened mediator or several independently-built ones, and how they relate to the already-shipped collector-broker (ADR-0006/0015) on `/run/bulkhead`, is deferred to a future ADR. (Open-q2 above — "should the broker itself use io_uring internally" — cannot be settled until that unification is decided.)
- **ADR-0035 (action authorization):** brokered async I/O flows through the OS-level resource-authorization layer, where every syscall/network/file action is default-deny and mediated.

---
*Evidence tags `[#N]` reference the bulkhead deep-research corpus (47 adversarially-verified reports) and `BULKHEAD-DESIGN-BRIEF.md`, kept in the design workspace alongside this repo.*
