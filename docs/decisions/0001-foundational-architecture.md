# ADR 0001 — Foundational architecture

- **Status:** Accepted
- **Date:** 2026-05-30

## Context

bulkhead is a from-scratch Linux distribution in which agent isolation, action
authorization, and model routing are first-class, system-level guarantees. This
ADR records the foundational decisions taken before any code, so the rationale
is part of the public history.

## Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | **Headless server appliance** (not a daily driver) | The security thesis is only credible on a small, single-purpose attack surface. |
| 2 | **Build host: Ryzen 9 5950X.** v1 validated in qemu (CPU-only), production on bare metal. | Decouples the build from hardware; v1 needs no GPU. |
| 3 | **Target GPU 12–16 GB.** | Sets model selection; rules out vLLM for local. |
| 4 | **systemd as init** (from v1) | Every chosen hardening feature — TPM-bound credentials, per-unit sandboxing, cgroup-tagged provenance — is a systemd feature. Buildroot supports `BR2_INIT_SYSTEMD`. |
| 5 | **Local engine: llama.cpp** (`llama-server`) | Small TCB, OpenAI + Anthropic-shaped HTTP, GGUF, packages cleanly. Build `GGML_NATIVE=OFF`, `LLAMA_CURL=OFF`. |
| 6 | **Models: Qwen2.5-3B-Instruct (v1 CPU), Qwen3-14B (prod GPU)**, both Q4_K_M, Apache-2.0 | Apache-2.0 avoids redistribution friction; 3B fits a small qemu guest, 14B fits 12–16 GB. |
| 7 | **Agent unit: custom namespace + cgroup + seccomp jail** | No container-runtime dependency; minimal, auditable, maximal control. |
| 8 | **Enforcement: eBPF-first, mature floor underneath** | seccomp + Landlock + caps + ns are the intrinsic fail-closed floor (applied at launch). eBPF is first-class but **observe-only** in v1; enforce/observe are separate program sets. A BPF-LSM deny layer comes later. |
| 9 | **Provenance in v1** | Hash-chained, Ed25519-signed, append-only audit log fed by an eBPF observe path; first-class from image #1. |
| 10 | **Updates: RAUC A/B atomic, verity bundles** (production) | Immutable, verified, rollback-capable. RAUC supports GRUB or the EFI backend on x86_64 — **not systemd-boot**. |
| 11 | **Network: Tailscale-only inbound, default-deny egress** | Smallest exposure; egress only to the Anthropic API + tailnet. |
| 12 | **Secrets: TPM-bound systemd credentials** | Never in repo or image. `--with-key=tpm2` on bare metal; host key in the qemu phase (vTPM unseal is unreliable, systemd #21747). |
| 13 | **License: AGPL-3.0-only** | Network-served; §13 closes the proprietary-SaaS-fork loophole that a permissive license leaves open. |
| 14 | **Build sequencing: Buildroot prototype → Yocto production** | Validate fast, then a reproducible, updatable production distribution. LFS only as optional learning. |
| 15 | **Kernel: 6.12 LTS** | Landlock ABI 6, mature BTF/CO-RE, settled LSM ordering, long support. |
| 16 | **Buildroot pinned at 2025.02.14** (LTS) | Mature, long-supported. Alternative considered: 2026.02 (newer LTS, fewer patch releases). The kernel is overridden to 6.12 regardless of the release default. |

## Roadmap surface (sizes the architecture, beyond v1)

Multi-agent orchestration · inter-agent capability delegation · human-in-the-loop
approval gate for sensitive actions · signed audit export + TPM attestation.

## Milestone plan

**v1 (Buildroot, CPU-only, qemu) — each milestone is a commit checkpoint:**

- **M0 — repo scaffolding.** License, hygiene, CI gates, BR2_EXTERNAL skeleton,
  docs. *(this commit)*
- **M1 — boots to systemd.** Pinned Buildroot; `bulkhead_defconfig` +
  `BR2_INIT_SYSTEMD` + TPM2_TSS + libopenssl + reproducible; 6.12 kernel + the
  security fragment; boots in qemu; floor assertions pass.
- **M2 — local inference.** llama.cpp package; Qwen2.5-3B staged via hashed
  fetch (not committed); hardened `llama-server.service`.
- **M3 — router + routing + Anthropic path.** Go router; routing rule; key via
  `LoadCredentialEncrypted`; `/source` endpoint; both routes demonstrated.
- **M4 — network boundary.** tailscaled (pinned ≥1.98.4); router binds
  `tailscale0`; nftables + dnsmasq egress; init-ordering graph.
- **M5 — provenance + fail-closed self-test.** cilium/ebpf observe-only
  collector; signed append-only log; boot self-test. Completes v1.

**Production (Yocto):** RAUC A/B + verity + read-only rootfs; SPDX SBOM + CVE;
off-repo signing (PKCS#11/KMS); measured boot + attestation; CUDA + Qwen3-14B;
BPF-LSM deny + capability-manifest enforcement; multi-agent + delegation +
approval gate.

## Consequences

- The TCB is deliberately small (kernel + systemd + collector + TPM).
- Configuration that could silently fail open (e.g. `CONFIG_CGROUP_BPF`, LSM
  ordering) is treated as untrusted until the boot self-test proves it; the
  self-test is the binding guarantee, not the config.
- Pins (Buildroot tag, kernel, model, tailscale, cilium/ebpf) are explicit and
  re-verified at build time, since upstream defaults drift.
