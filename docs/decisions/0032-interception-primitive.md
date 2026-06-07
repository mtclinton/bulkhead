# ADR-0032: Syscall interception primitive: Systrap default, KVM bare-metal only, seccomp-notify coarse

Status: Proposed
Date: 2026-06-07
Pillar: agent-isolation
Relates to: ADR-0031 (isolation substrate this trap serves), ADR-0033 (io_uring bypasses the trap).

## Context and problem statement

ADR-0031 commits bulkhead to a reimplemented-kernel (gVisor-class Sentry) boundary for the default tier, where no supported application syscall reaches the host kernel and host surface collapses from ~350 syscalls to ~68 allowlisted host calls the Sentry itself makes [#1]. That decision presupposes a *mechanism* by which guest syscalls are trapped, handed to the Sentry, and resumed. The trap mechanism is itself a security and performance boundary: it determines where the workload-to-Sentry transition lands, whether the primitive survives nested virtualization and ARM, and whether it can safely decide policy on syscall arguments. This ADR fixes that primitive. It does not revisit the reimplement-vs-forward-vs-filter substrate question (ADR-0031) nor the microVM/hostile-tier monitor choice.

## Decision drivers

- **Substrate independence.** bulkhead must run both on bare-metal appliances and inside cloud/nested guests, including ARM. A primitive that degrades or disappears under nested virt is a liability for the default tier [#4].
- **Steady-state interception cost** for syscall-bound and network-I/O-bound agent workloads, without coupling the security boundary to a vendor microbenchmark artifact [#4].
- **Soundness of argument inspection.** Any primitive used as the boundary must be able to decide policy on the *actual* arguments executed, including pointer-dereferenced data, without a time-of-check/time-of-use window [#4].
- **No dependence on deprecated kernel interfaces** whose removal would strand the boundary [#4].

## Considered options

- **gVisor Systrap (rewrite guest stub `mov;syscall` → `jmp` trampoline → shared memory → Sentry).** gVisor's own documentation states Systrap is "almost always the better choice" [#4]. Its fast path is a userspace stub rewrite with no per-syscall kernel trap and is substrate-independent: a nested VM does not multiply its cost the way it multiplies VM-exits [#4]. **Accepted as default.**
- **gVisor KVM (Sentry as ring-0 guest; hardware VM-exit per syscall).** Cheapest trap *only on bare metal*; its advantage erodes under nested virtualization because each guest VM-exit is re-mediated by the host hypervisor, and KVM is simply unavailable on ARM and clouds that do not expose nested virt [#4]. **Accepted, but restricted to bare-metal deployments.**
- **Legacy ptrace (`PTRACE_SYSEMU`).** A full ptrace stop on every syscall with a tracee↔tracer scheduler round-trip; gVisor calls it "quite slow" and it is deprecated, unsupported, and slated for removal [#4]. **Rejected** — building the boundary on a removal-bound interface is non-viable.
- **Raw seccomp-notify (`SECCOMP_RET_USER_NOTIF`) as the boundary.** Most portable and lowest-overhead, but the kernel man page is blunt that it "can not be used to implement a security policy": pointer-argument reads via `/proc/[tid]/mem` are racy and the `CONTINUE` fast path admits a TOCTOU window where the target rewrites arguments after the check [#4]. **Rejected as the boundary; accepted only as a coarse scalar/fd pre-filter** in front of the Sentry.

## Decision

bulkhead WILL use **gVisor Systrap as the default and only portable interception platform** across cloud guests, nested VMs, and ARM. bulkhead WILL select **KVM only on bare-metal appliance hosts** that bulkhead controls, where its VM-exit is the cheapest trap. bulkhead WILL **never ship the deprecated ptrace platform.** bulkhead MAY place **raw seccomp-notify as a cheap allow/deny pre-filter on scalar and fd-identity arguments in front of the Sentry**, but WILL NOT use it as a security boundary and WILL route every policy decision requiring pointer-argument dereference (e.g., pathname strings) to the Sentry [#4][#1].

## Consequences

### Positive

- Substrate-independent default: one code path covers bare metal, cloud, nested, and ARM, since Systrap needs no hardware virt extension [#4].
- Steady-state fast path avoids per-syscall kernel signal/ptrace transitions, so syscall-bound and network-I/O-bound agent workloads are not pinned to the worst-case trap cost [#4].
- KVM remains available as a tuning lever for bare-metal appliances without becoming a portability dependency [#4].
- Pointer-argument policy is decided in the memory-safe Sentry, closing the seccomp-notify TOCTOU class by construction [#4].

### Negative / costs

- Two interception paths to build, test, and harden (Systrap everywhere, KVM on bare metal) instead of one.
- A seccomp-notify pre-filter adds a third moving part whose contract must be strictly limited to scalar/fd decisions, with discipline required so it never silently becomes load-bearing for pointer-dependent policy.
- No direct Systrap-vs-KVM nanosecond comparison on identical hardware exists in the verified evidence; the cloud-guest ordering rests on gVisor's qualitative documentation, not independent measurement, so bare-metal KVM enablement should be gated on bulkhead's own profiling rather than published deltas [#4].

### Residual risks the OS cannot touch

- The interception primitive only governs the workload→Sentry transition; a **Sentry-internal vulnerability or a host-kernel 0-day in the ~68 calls the Sentry makes** sits beneath this choice and is unaffected by it (scoped in ADR-0031).
- **CPU side-channels** are orthogonal to any trap mechanism.
- The seccomp-notify TOCTOU race is *avoided* by not using it as the boundary, not *solved*; any future drift toward letting it decide pointer-argument policy would silently reintroduce the race [#4].

## Confidence & open questions

High confidence on the mechanism ranking and the substrate-specific KVM crossover — both quote gVisor primary documentation and the kernel man page directly [#4]. Lower confidence on the precise cloud-guest Systrap-vs-KVM latency delta, which the corpus flags as resting on qualitative docs and a single 2022-rooted independent benchmark lineage [#4]. **Open:** whether the seccomp-notify scalar pre-filter earns its keep versus letting the Sentry decide everything — to be settled by profiling, not assumed. **Open:** the exact bare-metal workload threshold (high-syscall-rate/I/O-bound) at which KVM enablement is worth its operational cost on appliance hosts [#4].

## Evidence (source reports)

- [#4] *Syscall-interception primitives: Systrap vs KVM vs ptrace vs seccomp-notify* — 25/27 verified. Source of the "Systrap almost always better," "KVM bare-metal only," ptrace-deprecation, and seccomp-notify TOCTOU findings.
- [#1] *Syscall-interception sandbox architectures (reimplement vs forward vs filter)* — 23/23 verified. Establishes the reimplemented-Sentry substrate this primitive serves and the ~350→~68 host-surface collapse.

## Related ADRs

- **ADR-0031** (isolation substrate: reimplement > intercept-and-forward > filter; Firecracker for the hostile tier) — this ADR selects the trap mechanism for the reimplemented boundary that ADR-0031 mandates.
- **ADR-0033** (io_uring: broker or ban) — io_uring bypasses syscall interception entirely via shared rings, so it must be disabled/brokered for any tier relying on the Systrap/KVM trap (or the Sentry's own interception) to remain the choke point.

---
*Evidence tags `[#N]` reference the bulkhead deep-research corpus (47 adversarially-verified reports) and `BULKHEAD-DESIGN-BRIEF.md`, kept in the design workspace alongside this repo.*
