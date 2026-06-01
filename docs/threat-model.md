# bulkhead threat model

> Living document. v1 scope. Expanded as enforcement and multi-agent features
> land.

## What we are protecting

- **The host and its credentials.** A misbehaving or compromised agent must not
  reach the Anthropic API key, the audit-signing key, other agents' data, or the
  host's authority.
- **The integrity of provenance.** The record of what each agent did must be
  tamper-evident even against an attacker who gains code execution.
- **The network boundary.** The appliance must not become an exfiltration or
  pivot point: no unsanctioned inbound, no unsanctioned egress.

## Trust boundaries

```
   tailnet peer ──▶ [ tailscale0 ] ──▶ bulkhead-router (unprivileged)
                                              │  routes
                          ┌───────────────────┴───────────────────┐
                          ▼                                        ▼
                   llama-server (local, 127.0.0.1)        Anthropic API (egress-allowlisted)
                          │                                        ▲
                          └──── observed by ───┐                   │ key from TPM-bound cred
                                               ▼
                                   bulkhead-collector (privileged, CAP_BPF)
                                               │
                                               ▼
                                   append-only signed audit log (persistent)
```

- **Untrusted:** request content arriving over the tailnet; any future agent
  workload.
- **Semi-trusted:** the router and llama-server — unprivileged, sandboxed,
  observed. A compromise here must not yield host authority, secrets it was not
  given, or the ability to tamper with provenance.
- **Trusted (TCB):** the kernel + its security config, systemd, the collector,
  the boot self-test, and the TPM. Kept deliberately small.

## Adversaries considered

1. **Compromised/malicious agent or model output** attempting to read secrets,
   write outside its grant, spawn processes, or exfiltrate over the network.
2. **Compromised router/llama-server** (e.g. via a parsing bug) attempting to
   escalate, reach the Anthropic key, disable provenance, or open egress.
3. **Local attacker with disk access** attempting to forge or truncate the audit
   log, or recover secrets from an image or the repo.

## Guarantees the design aims to provide

- **Fail-closed confinement.** Services/agents cannot run without their seccomp +
  Landlock + capability + namespace profile; a boot self-test attempts forbidden
  actions and refuses to launch if any is *not* denied.
- **No secret at rest in distributable artifacts.** Nothing sensitive in the repo
  or any image; the Anthropic key is TPM-bound and only ever present in a
  unit-private tmpfs credential at runtime.
- **Default-deny network.** Tailscale-only inbound; egress only to the Anthropic
  API + tailnet, enforced in the kernel (nftables/cgroup-eBPF).
- **Tamper-evident provenance.** Hash-chained, Ed25519-signed, append-only log;
  chain head anchored off-box, so on-disk tampering or truncation is detectable.

## Assumptions

- The kernel and its pinned security configuration are trusted and correctly
  built (BTF present, `bpf`+`landlock` in the active LSM list, `CONFIG_CGROUP_BPF`
  set). The boot self-test exists precisely because configuration can silently
  drift or fail open.
- The TPM (or persistent host key in the VM phase) is the root of trust for
  secret sealing and audit-log signing.
- Tailscale's control plane and the operator's tailnet ACLs are trusted for
  network identity.

## Non-goals (v1)

- Defending a daily-driver / general-purpose workload (bulkhead is an appliance).
- BPF-LSM *enforcement* (deny) — v1 uses eBPF for provenance only; enforcement is
  the mature floor (seccomp/Landlock/ns/cgroup). The deny layer is a later
  increment.
- Protecting against a compromised TPM or a malicious physical attacker with
  arbitrary hardware access.
- Remote attestation (deferred; the measured-boot PCRs + a TPM AK are the seam — ADR-0008).
  The audit-log signing key is now TPM-sealed (ADR-0008, sealed to PCR 7, fail-closed); the
  measured-boot infrastructure (OVMF/GRUB/kernel/systemd-pcrphase) is in place, with live
  firmware PCR measurement validated on bare metal (qemu vTPM can't, per ADR-0001 #12).
