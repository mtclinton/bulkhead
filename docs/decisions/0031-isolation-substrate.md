# ADR-0031: Isolation substrate: reimplemented-kernel default, Firecracker hostile tier, no hand-rolled VMM

Status: Accepted (default tier) — runsc substrate integration slices 1-6 shipped + live-proven 2026-06-15: packaged → host-surface collapse → agent-under-Sentry → mediated egress → real agent loop → production runsc-run form → DEPLOYABLE bulkhead-agent-runsc@ unit
Date: 2026-06-07
Pillar: agent-isolation
Relates to: ADR-0032 (interception primitive), ADR-0033 (io_uring broker), ADR-0034 (egress), ADR-0035 (action authorization), ADR-0036 (model-routing quarantine runs on this substrate), ADR-0037 (multi-agent domains reuse this substrate), ADR-0038 (confidential computing rejected); refines the agent-isolation pillar of ADR-0001.
Supersedes-in-part: ADR-0004 / ADR-0005 — the shipped shared-kernel BPF-LSM cgroup-keyed enforce (E0–E3) is retained for the trusted/namespace tier but is no longer the default substrate (see *Migration* below).

## Context and problem statement

Bulkhead's first pillar is agent isolation as an OS-level guarantee, under the explicit threat model that the adversary already has code execution inside the sandbox — i.e., a prompt-injection-to-RCE chain has already succeeded. The question is not "how do we keep the agent honest" but "given a compromised agent, what boundary still stands between it and the host." That makes the substrate choice the load-bearing decision for the entire pillar: every property above it inherits its post-compromise containment.

Two sub-questions must be answered together: (1) what *kind* of boundary do we put under the default agent tier, and (2) do we build that boundary ourselves or reuse a hardened artifact. The bulkhead body of work carries sibling prototype repos at github.com/mtclinton — `mini-sentry` (a minimal userspace kernel in Go inspired by gVisor, intercepting syscalls via ptrace SYSEMU) and `mini-firecracker` (a toy Firecracker-style KVM VMM in Go), plus `gvisor-exec` (a runsc CLI wrapper) — so the build-vs-reuse tension is live, not hypothetical. (These are exploratory siblings, not in this appliance repo's `src/`, which today ships the BPF-LSM substrate of ADR-0004/0005.)

## Decision drivers

- **Post-compromise containment, not autonomy.** The boundary must hold after RCE inside the sandbox; permission-prompt reduction is a separate concern.
- **Host attack-surface minimization.** Fewer host code paths reachable from the guest is the primary metric.
- **Memory-safe, auditable trusted computing base.** The boundary's own code is the new attack surface; its size and language matter.
- **Avoid reintroducing solved bug classes.** A C reimplementation of device emulation is a known historical hazard.
- **Enumerable, not open-ended, cost.** Compatibility gaps must be bounded and knowable.

## Considered options

- **Filter only (seccomp / namespaces, e.g. bubblewrap).** Rejected as the default/hostile boundary. Every *allowed* syscall executes host-kernel code directly, so it buys zero attack-surface reduction [#1]. Because it grants the agent an unprivileged user namespace (`CLONE_NEWUSER`), it hands the attacker the exact primitive the recurring nf_tables / OverlayFS LPE CVEs require [#8]. One kernel CVE is a tenant escape [#8][#10]. Acceptable only for a trusted/low-threat tier.
- **Intercept-and-forward (thin PTRACE_SYSEMU).** Rejected. It forwards the un-emulated tail of syscalls to the host kernel, reintroducing host surface per forwarded call, and inherits classic-ptrace overhead. It structurally cannot match reimplementation [#1].
- **Reimplemented kernel (gVisor-class Sentry).** **Accepted as default.** No supported application syscall reaches the host; host surface collapses from ~350 syscalls to ~68 allowlisted calls the Sentry itself makes [#1]. A Sentry compromise alone is, by gVisor's own policy, explicitly *not* a host escape [#10]. Cost is a *bounded* compatibility gap (277/351 syscalls; io_uring partial; `vmsplice`/`userfaultfd` unimplemented) — enumerable, not open-ended [#1].
- **Reuse Firecracker microVM (hostile tier).** **Accepted for the hostile tier.** Separate guest kernel; ~50k LOC of memory-safe Rust and five emulated devices vs QEMU's ~1.4M lines of C [#9].
- **Hand-rolled C VMM for the boundary.** **Rejected.** It reintroduces precisely the VENOM bug class (CVE-2015-3456) — a host escape that hid in QEMU's floppy controller for over a decade [#9]. Defensible only under seL4-level formal assurance (~20 person-years) or a radical device-surface reduction off-the-shelf monitors can't match [#9] — neither applies.

## Decision

Bulkhead **will** make a separate-kernel boundary mandatory for the default and hostile agent tiers. The **default** isolation boundary is a reimplemented-kernel Sentry (gVisor-class) — the approach the `mini-sentry` prototype demonstrated, upgraded for production from that prototype's ptrace-SYSEMU interception to Systrap (ADR-0032). The **hostile tier** runs inside a **reused Firecracker microVM** (Cloud Hypervisor where more device breadth is required). Bulkhead **will not** ship a hand-rolled VMM (neither a C monitor of the QEMU/VENOM class nor our own `mini-firecracker` Go prototype) as any tier's boundary. Namespace+seccomp is permitted **only** for an explicitly trusted, low-threat tier — never as the default. The `mini-firecracker` Go prototype is retained as a learning artifact and for control-plane use, not as the hostile-tier guest boundary.

**Canonical tier taxonomy (used verbatim across ADR-0031–0038):**
- **trusted/low-threat** — namespace+seccomp (bubblewrap-class) permitted.
- **default** (a.k.a. *observed/authorized*) — reimplemented-kernel gVisor-class Sentry, intercepted via Systrap (ADR-0032).
- **hostile** — reused Firecracker microVM (separate guest kernel).

## Migration: relationship to the shipped BPF-LSM substrate

This roadmap is the **target**, not the present state. bulkhead today enforces agent isolation with a
SHARED-kernel BPF-LSM (E0–E3, ADR-0004/0005): per-agent cgroup-keyed hooks (`bpf`, `ptrace_access_check`,
`socket_connect`, `task_fix_setuid`, `capset`) fire on the agent's OWN host syscalls. That design *is* the
namespace+seccomp-on-a-shared-kernel posture this ADR reclassifies as the trusted/low-threat tier only.
Moving to a separate-kernel default changes *where mediation lives*:

- **Trusted/namespace tier:** the shipped BPF-LSM enforce is RETAINED unchanged — the agent still issues
  host syscalls, so the host LSM hooks still observe it.
- **Default (Sentry) tier:** the agent's syscalls are serviced inside the Sentry and never reach the host
  LSM dispatcher, so the E1/E2/E3 hooks no longer observe the agent (host hooks would fire only on the
  Sentry's own ~68 host calls). Resource mediation (ADR-0035) and egress (ADR-0034) therefore RELOCATE from
  the host BPF-LSM into the Sentry's own interception. ADR-0004/0005's cgroup-keyed enforce is **superseded
  as the default substrate**, not deleted.
- **Hostile (Firecracker) tier:** the agent runs in a separate guest kernel; the host BPF-LSM sees only the
  VMM's host calls — the same relocation of mediation into the guest/VMM boundary.

This ADR is therefore **Supersedes-in-part** for ADR-0004/0005 (and ADR-0034 is supersedes-in-part for the
ADR-0006/0009/0010 egress allowlist), not a pure refinement. Until the Sentry/Firecracker substrate ships,
the BPF-LSM substrate remains bulkhead's authoritative isolation; this series describes where it goes next.

## Consequences

### Positive

- Host syscall surface for the default tier collapses ~350→~68 host calls the Sentry itself makes [#1] (NB: brokered I/O per ADR-0033 and the egress proxy per ADR-0034 add their own host-side surface, accounted there — the agent-reachable host surface is the Sentry's ~68 *plus* those mediators'); a Sentry breach is — by gVisor's own severity policy — not by itself a host escape [#10] (the ~68-call host surface still sits beneath it).
- Hostile-tier TCB is ~50k LOC memory-safe Rust / 5 devices instead of ~1.4M C [#9], and we inherit Firecracker's hardening rather than re-deriving it.
- We sidestep the VENOM-class decade-hidden device-emulation bug entirely [#9].
- This separate-kernel posture is bulkhead's concrete differentiator versus containerless incumbents (Anthropic `sandbox-runtime`, Daytona default) [#8][#10].

### Negative / costs

- A bounded but real compatibility gap on the Sentry path (io_uring partial; `vmsplice`/`userfaultfd` unimplemented) [#1]; some workloads need the microVM tier.
- Platform overhead exists and is workload-specific; gVisor publishes only relative graphs, so any "order-of-magnitude" gap figure is unsourced [#1].
- Operational dependency on upstream Firecracker/gVisor security response.
- We forgo shipping our own C VMM despite prototype investment.

### Residual risks the OS cannot touch

- **CPU side-channels and hypervisor/KVM 0-days** sit beneath every boundary, reimplemented or microVM [#10][#36]. No tier removes them.
- A stronger kernel boundary **buys nothing against the attacks that actually occurred** in 2024–2026 — those were egress-policy and orchestrator-layer failures, not kernel escapes [#26]. This ADR hardens the boundary but does not address the empirically dominant failure surface, which is why bulkhead must spend equally on egress (ADR-0034) and authorization (ADR-0035).

## Confidence & open questions

High confidence on the substrate ranking and the reject-C-VMM call: reports #1, #8, #9, #10 are strongly and consistently sourced (22–24 verified claims each). Open questions: (1) the default/hostile **tier-assignment policy** — which workloads get pushed from Sentry to Firecracker, and on what signal; (2) whether Cloud Hypervisor's larger device set is worth its surface for any tier; (3) `sandprint`-style observed-syscall profiling as a validated *complement* to the substrate [#26]. The interception primitive (Systrap vs KVM) and io_uring handling are decided in separate ADRs.

## Feasibility spike — gVisor/runsc viability (2026-06-15)

A time-boxed spike retired the largest "can we even get there" unknown for this ADR. It does NOT
revisit the defer decision (that stays grounded in #26 — the 2024–26 real breaks were egress/
orchestrator, not kernel escapes, which is why ADR-0034 shipped first); it asks only whether the
gVisor-Systrap path is viable for this appliance WHEN scheduled. All reproduced on the dev host with
runsc release-20260413:

- **runsc runs, rootless, under BOTH platforms.** `runsc --rootless --ignore-cgroups
  --platform=systrap do <cmd>` and `--platform=kvm` both execute a workload. Systrap ran with no
  hardware-virt / nested-KVM dependency — ADR-0032's substrate-independence claim, confirmed live.
- **Host-surface collapse, demonstrated.** A workload inside the sandbox reports kernel `4.4.0`
  (gVisor's reimplemented kernel) and `dmesg` "Starting gVisor…", NOT the host's 6.12. The
  application's syscalls are serviced by the Sentry, not the host — this ADR's load-bearing property.
- **A real bulkhead agent runs under the Sentry, unmodified.** The shipped `bulkhead-agent` (stdlib
  Go) builds and runs under runsc/Systrap; under `--network=none` its probe correctly reports NOROUTE
  (network unreachable). The Go runtime + net syscalls are gVisor-compatible.
- **Packaging is trivial.** runsc is a single statically-linked ~63 MB Go binary (no dynamic deps), so
  a Yocto recipe is "install the release binary" — no bazel, no meta-virtualization layer (none present).
- **`mini-sentry`** (sibling prototype, ~5.6k LOC Go, ptrace-SYSEMU) validates the *concept*; runsc
  with Systrap is the production vehicle — exactly the "approach mini-sentry demonstrated, upgraded to
  Systrap" this ADR specifies.

**Integration shape (deferred cost, est. M–L when scheduled).** runsc becomes the default-tier agent
jail's OCI runtime; the namespace/E0–E3 tier is retained for trusted/low-threat (per *Migration*).
bulkhead's egress mediation is FAVOURABLY placed: the egress proxy is already host-side and reached
over a unix socket, so an agent moved into a Sentry keeps the SAME mediated egress — the proxy/router
UDS legs are bind-mounted into the sandbox (gVisor supports AF_UNIX + bind mounts); the egress
guarantee need not relocate into the Sentry the way host-LSM mediation would. Remaining work: an
OCI-bundle agent launcher, the UDS bind-mounts + resource/seccomp config, io_uring kept disabled
(ADR-0033; gVisor's io_uring is partial anyway), and a `make verify-*` proving a sandboxed agent with
its mediated egress intact. **Verdict: GO on feasibility — no blocker; path clear and bounded.**

## Integration status — runsc as the default-tier substrate (slices 1-5, 2026-06-15)

The spike's "remaining work" is now substantially done and live-proven in the BOOTED APPLIANCE (not just the dev host), with NO change to the agent or proxy code:

- **Slice 1 — packaged + host-surface collapse** (`make verify-runsc`, commit 45c28f3). runsc is in the image (Yocto recipe, release-20260413, sha256-pinned static binary) and runs via Systrap-rootless; a workload under runsc reports gVisor's reimplemented kernel **4.4.0**, not the host's 6.6.127 — the Sentry is interposed and the host syscall surface is collapsed.
- **Slice 2 — production agent under the Sentry** (`make verify-runsc`, commit 228e90a). The unmodified `/usr/bin/bulkhead-agent` runs under gVisor (Go runtime + net stack are Sentry-compatible); the sandbox gives it NOROUTE + ISOLATED (no direct egress). `io_uring_setup` is **ENOSYS** under the Sentry — so ADR-0033's io_uring ban is delivered by the SUBSTRATE itself (gVisor doesn't expose io_uring), no per-jail seccomp filter required (stronger than the "partial" the spike expected).
- **Slice 3 — mediated egress preserved** (`make verify-runsc-egress`, commit dc2cf3b). With `runsc --host-uds=open` the sandboxed agent reaches the HOST egress-proxy UNIX socket across the Sentry boundary, and the host proxy makes the actual egress. The ADR-0034 boundary holds UNCHANGED: no direct egress, the proxy is the only path, the allowlist is enforced (PROXY-DENY), and every destination is signed into the /data chain (which verifies). Host-side egress mediation transfers to the substrate for free — confirming the spike's favorable-placement finding.

- **Slice 4 — a full real agent loop under the Sentry** (`make verify-runsc-agent`, commit 77e2b98). Stronger than the probe: the whole perceive→decide→act loop runs under gVisor with BOTH mediated channels — the model leg over the router UDS (the loop reached a model FINAL) and the web leg through the egress proxy (HTTP 200), the egress signed. The confined-jail agent, hosted by the substrate.
- **Slice 5 — the PRODUCTION runtime form** (`make verify-runsc-run`, commit facbc93). `runsc do` is testing-only; the deployable runtime is `runsc run` over an OCI bundle, and a real jail needs a MINIMAL rootfs (root=/ would expose the whole host fs — a regression vs the systemd jail's ProtectSystem=strict). Built a minimal rootfs (ONLY the agent binary + the two UDS legs bind-mounted in; host fs not exposed) and ran the real agent loop under `runsc run` — both legs mediated, egress signed. The secure production form works.

- **Slice 6 — the DEPLOYABLE unit** (`make verify-runsc-unit`, commits dd7886f + the FILES fix). `systemctl start bulkhead-agent-runsc@<inst>` launches a substrate-jailed agent: the unit ExecStarts `bulkhead-agent-runsc-launch`, which builds a per-instance minimal-rootfs OCI bundle and `runsc run`s it. The task rides a `0400` credential (file CONTENT, never JSON/unit syntax — injection-safe, reusing ADR-0015's channel); the bundle is reaped on stop (no /run leak). Live-proven: a real agent loop, both legs mediated, egress signed. A sibling tier to `bulkhead-agent-confined@` (netns), now with gVisor's host-surface collapse + io_uring-ENOSYS underneath.

So the default-tier substrate is **integrated and operator-deployable**: a real agent runs in a minimal-rootfs Sentry (host fs not exposed) with host-surface collapse + io_uring-ENOSYS + both mediated legs (`--host-uds=open` is the load-bearing enabler) + signed provenance + injection-safe task, launchable via systemd. **Refinements remaining:** non-root uid inside the sandbox (currently uid 0, gVisor-contained); per-instance resource limits + a tightened mount set; default-tier (substrate) vs trusted-tier (namespace/E0–E3, retained) *selection policy* per *Migration*; and the hostile-tier Firecracker microVM (this ADR's other path). The KVM platform (vs Systrap) for bare metal is a config flip when nested-KVM is available.

## Evidence (source reports)

- [#1] Syscall-interception sandbox architectures: reimplement vs forward vs filter (~350→68 collapse; bounded gap).
- [#8] Bubblewrap+seccomp for hostile agents (shared-kernel; `CLONE_NEWUSER` LPE primitive).
- [#9] Roll-your-own VMM vs Firecracker/gVisor (~50k Rust/5 devices vs ~1.4M C; VENOM CVE-2015-3456).
- [#10] Agent-sandbox isolation boundary: claim vs reality (one CVE = tenant escape; Sentry breach ≠ host escape).
- [#26] Isolation primitives for untrusted agent code (real breaks were egress/orchestrator, not kernel).

## Related ADRs

- **ADR-0032** — Interception primitive (Systrap default; KVM bare-metal-only): determines *how* the chosen Sentry substrate intercepts syscalls.
- **ADR-0033** — io_uring broker-or-ban: the substrate's observability premise depends on not exposing a ring.
- **ADR-0034** — Egress as a structural guarantee: the failure surface this boundary does not cover.
- **ADR-0035** — Action authorization (resource at OS, semantic above it): rides on top of this boundary.
- **ADR-0036** — Model-routing quarantine: the quarantined (Q-LLM) model runs as its own isolation domain on this substrate.
- **ADR-0037** — Multi-agent isolation domains: each agent domain reuses this substrate as its per-agent boundary.
- **ADR-0038** — Confidential computing (SEV-SNP/TDX) rejected: scoped against the same threat model and host-ownership assumptions used here.

---
*Evidence tags `[#N]` reference the bulkhead deep-research corpus (47 adversarially-verified reports) and `BULKHEAD-DESIGN-BRIEF.md`, kept in the design workspace alongside this repo.*
