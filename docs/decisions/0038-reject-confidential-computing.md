# ADR-0038: Reject confidential computing (SEV-SNP / TDX) for the single-tenant threat model

Status: Proposed
Date: 2026-06-07
Pillar: agent-isolation (hardware)
Relates to: ADR-0031/0032 (the separate-kernel boundary this declines to put CC beneath), ADR-0036 (shared sub-boundary residual).

## Context and problem statement

Bulkhead's isolation substrate is a separate-kernel boundary — gVisor-class reimplementation (the default tier) and a reused Firecracker microVM (the hostile tier) (ADR-0031, ADR-0032), and explicitly **not** a hand-rolled C VMM (ADR-0031). A recurring question for any from-scratch appliance is whether hardware confidential computing (AMD SEV-SNP / Intel TDX) belongs *beneath* that boundary as a hardware isolation primitive. This ADR settles that, because the answer is determined by the operator model, not by the strength of the hardware.

Bulkhead's deployment is **single-tenant**: the operator owns and trusts the physical host and the hypervisor; the *agent* is the untrusted workload running as the in-guest tenant. CC's entire value proposition is inverted relative to this — it exists to defend a guest against a *malicious host/VMM* the operator places outside the CVM TCB [#36]. That adversary is excluded by construction here.

## Decision drivers

- **Threat-model fit.** Adopt a primitive only when it defends an adversary in scope. CC's adversary (a hostile host) is exactly the party the operator already controls [#36].
- **Attack-surface accounting** (the altitude test, [#16]): a lowered control must reduce, not enlarge, the mediatable surface. CC's surveyed CVE corpus is **54% firmware bugs and 39% improper-validation** of the host→guest interface (81% of CVEs are host-to-guest), and a CVM's TCB *includes the full guest OS* — millions of LoC — so CC does not shrink the trusted base [#36].
- **Dependency irrevocability.** SEV-SNP attestation roots in the AMD PSP running AMD-signed firmware (VCEK → AMD root); TDX roots in Intel's PCS. Both are non-removable vendor signing dependencies, and a firmware update silently broke report parsing in production (AMD v3→v4 on 2025-10-27) [#36].
- **No load-bearing gain.** CC provides confidentiality/integrity vs. a software host plus launch attestation; it explicitly does **not** provide availability/DoS isolation and is not Common-Criteria evaluated [#36].

## Considered options

1. **Adopt CC as the primary isolation boundary.** *Rejected.* It defends the wrong direction (host→guest) for a model where host is trusted and guest is hostile; the separate-kernel substrate (default Sentry; hostile-tier Firecracker microVM) already handles untrusted-guest containment, which CC does not specifically improve [#36].
2. **Adopt CC as mandatory defense-in-depth beneath the VMM.** *Rejected as a default.* The conditional gain (compromised-but-owned host, malicious insider, breached management plane) is real but bounded, and is bought at the cost of the dominant firmware/validation CVE class plus an irrevocable vendor-signing and parser-maintenance liability [#36].
3. **Treat CC as an optional, operator-justified mode.** *Accepted as the only conditional path.* Permitted solely where the operator's own threat model genuinely includes a compromised host or hostile insider — never as bulkhead's advertised guarantee.
4. **No CC; the separate-kernel substrate (Sentry default; Firecracker hostile tier) is the load-bearing boundary.** *Accepted (default).* Consistent with ADR-0031/0032.

## Decision

Bulkhead will **not** adopt SEV-SNP or TDX as an isolation primitive. The load-bearing boundary is the separate-kernel substrate — the gVisor-class Sentry (default) and the reused Firecracker microVM (hostile tier), per ADR-0031/0032. CC is offered only as an **optional, off-by-default mode** an operator may enable when their threat model explicitly includes a compromised-but-owned host or malicious insider — and it is never marketed as a bulkhead OS-level guarantee.

## Consequences

### Positive

- No new firmware/attestation attack surface in the default build; bulkhead's mediatable boundary stays the VMM, where it can be reasoned about [#36].
- No hard dependency on AMD/Intel signing infrastructure, closed firmware, or vendor TCB-recovery cadence; no attestation-parser maintenance treadmill in the critical path [#36].
- Honest positioning: bulkhead does not claim a hardware guarantee against an adversary it does not face.

### Negative / costs

- No memory-encryption benefit against cold-boot/DMA-class data exfiltration of a physically present attacker, and no defense if the operator's *own* host is later compromised — both must be addressed by physical/operational controls instead [#36].
- Operators who do face a hostile-host model must opt into CC explicitly and accept its costs themselves (DDR5/TDX preferred for the narrow physical-tamper edge, plus parser maintenance) [#36].

### Residual risks the OS cannot touch

- **CPU side-channels and hypervisor/KVM 0-days** sit beneath every boundary bulkhead builds; CC would not have removed them (side-channel resistance is explicitly the guest's responsibility even under CC) [#36][#10].
- **Physical-bus adversaries** (sub-$50 DDR4 interposers; DDR5 interposition) are out of scope for both bulkhead and the CC vendors themselves [#36].
- A **compromised-but-owned host or malicious insider** is unmitigated in the default model — this is the precise gap CC would fill, and bulkhead consciously declines to close it in software [#36].

## Confidence & open questions

High confidence: the CVE taxonomy (54%/39%, 81% host→guest), the inverted-threat-model argument, the irrevocable vendor-signing chain, and the v3→v4 parser break are all strongly sourced [#36]. The corpus closes June 2024, so the firmware-dominant trend is if anything understated for 2025–2026. Open question: if a future bulkhead deployment targets shared/managed hosting (breaking the single-tenant premise), this ADR must be revisited — CC's threat model would then become in-scope.

## Evidence (source reports)

- [#36] SEV-SNP vs TDX: real isolation or attestation theater — CVE taxonomy, inverted threat model, attestation chain, parser fragility.
- [#16] When pushing safety into the OS actually wins — the altitude test (a lowered control must not become net new attack surface).
- [#10] Agent-sandbox isolation boundary: claim vs reality — CPU side-channels and hypervisor 0-days as sub-boundary residuals.

## Related ADRs

- **ADR-0031 / ADR-0032** (reimplemented-kernel Sentry default; reused Firecracker microVM hostile tier; **no hand-rolled C VMM** — owned by ADR-0031) — the boundary this ADR declines to put CC beneath, and the load-bearing containment instead of CC.
- **Shared sub-boundary residual:** the CPU-side-channel / hypervisor-0-day floor enumerated here is the same one carried by ADR-0031/0032/0033/0036. There is no separate residual-risk ADR.

---
*Evidence tags `[#N]` reference the bulkhead deep-research corpus (47 adversarially-verified reports) and `BULKHEAD-DESIGN-BRIEF.md`, kept in the design workspace alongside this repo.*
