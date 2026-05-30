# bulkhead architecture

> Living document. Reflects the design as of the v1 milestone. Decisions and
> their rationale are recorded as ADRs under [decisions/](decisions/).

## Thesis

On a general-purpose Linux system, an agent process inherits the full authority
of the user that launched it. bulkhead inverts that default: **agent action
authorization is an OS primitive.** Confinement is systemic and non-optional —
every agent runs inside a kernel-enforced sandbox, every capability is
explicitly granted, and every security-relevant action is recorded with full
provenance.

bulkhead is a single-purpose **appliance**, not a daily driver. That is a
security decision: the guarantees are only credible on a small, single-purpose
attack surface.

## Layers

```
┌─ integrity / boot ──────────────────────────────────────────────┐
│  v1: qemu direct -kernel boot                                    │
│  prod: GRUB or EFI backend + EFI partition; RAUC A/B (verity)    │
│  TPM2 (vTPM via swtpm in the VM; real TPM on bare metal)         │
├─ kernel security substrate — one pinned kernel (6.12 LTS) ───────┤
│  cgroup v2 · namespaces · seccomp · Landlock (ABI 6) · BPF-LSM   │
│  lsm=landlock,lockdown,yama,bpf  (pinned on cmdline + CONFIG_LSM) │
├─ enforcement floor — intrinsic, fail-closed ────────────────────┤
│  per process at launch: seccomp + Landlock + dropped caps + ns   │
│  egress: nftables default-deny + dnsmasq→nftset (authoritative)  │
│  systemd IPAddressDeny=any on bulkhead.slice (coarse 2nd layer)  │
├─ service plane — unprivileged ──────────────────────────────────┤
│  llama-server  (127.0.0.1, CPU in v1 / CUDA in prod)             │
│  bulkhead-router  (Go; binds the tailnet interface)              │
├─ control + provenance plane ────────────────────────────────────┤
│  bulkhead-collector  (Go + cilium/ebpf; CAP_BPF; privileged)     │
│  observe-only BPF-LSM → ring buffer → hash-chained Ed25519 log   │
│  fail-closed boot self-test · capability-manifest format         │
├─ network identity ──────────────────────────────────────────────┤
│  tailscaled (kernel mode, tailscale0) — tailnet-only inbound     │
└──────────────────────────────────────────────────────────────────┘
```

## Enforcement model: eBPF-first, mature floor underneath

The distinctive layer is eBPF — but it is **not** the sole gate. Two things eBPF
gives us are kept strictly separate:

- **Enforcement floor (fail-closed, applied at process launch):** seccomp
  (syscall allowlist) + Landlock (filesystem confinement) + dropped capabilities
  + network/cgroup namespaces. These are intrinsic to launching a process — an
  agent *cannot* run without them, and setup failure is loud and local.
- **Provenance fabric (observe-only, first-class):** eBPF programs attached to
  LSM hooks (`SEC("lsm/...")`) that **always return 0**. Because the LSM
  dispatcher (`call_int_hook`) short-circuits on the first denial and `bpf` is
  ordered last, an observe-only program cannot weaken a decision an earlier LSM
  (or seccomp, which runs even earlier at syscall entry) already made. It
  records; it does not gate.

A BPF-LSM **deny** layer is a later increment, added once the observe path and
capability-manifest format are proven — never as v1's only enforcement.

### Fail-open traps we explicitly design against

1. **`CONFIG_CGROUP_BPF=y` is mandatory.** systemd's `IPAddressDeny=` is
   implemented with a cgroup/eBPF program; without this config option systemd
   logs a warning and runs **with no firewall**. Mitigation: it is in the kernel
   fragment *and* the boot self-test actively attempts a forbidden egress
   connect and requires `EPERM`.
2. **`lsm=` order is load-bearing.** The observe-only safety argument depends on
   `bpf` being ordered after the enforcing LSMs. The cmdline is pinned in
   version control and the resolved order is asserted at boot.
3. **vTPM credential binding is ephemeral.** TPM2-sealed credentials only decrypt
   on the same TPM/vTPM instance, and swtpm NVRAM resets brick them. v1 seals on
   first boot / uses the host key; the credential store lives on a **persistent**
   partition, not a RAUC rootfs slot.
4. **Init-order race = unrestricted-egress window.** The router starts
   `After=/Requires=` the egress floor, tailscaled, and the self-test gate —
   never before.
5. **`GGML_NATIVE` SIGILL.** llama.cpp is built `-DGGML_NATIVE=OFF` so the image
   is portable across CPU models; the qemu `-cpu` is pinned.

## Components

| Component | What | Privilege |
|---|---|---|
| kernel (6.12 LTS) | security substrate; BTF for CO-RE | — |
| systemd | init, service supervision, sandboxing, credentials | pid 1 |
| llama-server | local inference (llama.cpp), OpenAI + Anthropic-shaped HTTP | unprivileged, 127.0.0.1 |
| bulkhead-router | Go; request routing, `/source`, Anthropic egress | unprivileged |
| bulkhead-collector | Go + cilium/ebpf; provenance, boot self-test | CAP_BPF/CAP_PERFMON |
| tailscaled | tailnet membership (kernel mode) | system |
| nftables + dnsmasq | default-deny egress + DNS-driven Anthropic allowlist | system |

The split between an **unprivileged router** and a **privileged collector** is
deliberate: only the trusted collector loads BPF, so a router compromise cannot
detach the provenance layer. Agents (a later milestone) get strictly less.

## Model routing

The router exposes an OpenAI-compatible endpoint and selects a backend per
request:

- An explicit `route` field (`"local"` | `"api"`) wins when present.
- Otherwise a **prompt-length threshold** decides: short → local llama.cpp,
  long → Anthropic API. Default is local.

The Anthropic API key is read at runtime from `$CREDENTIALS_DIRECTORY` (a
TPM-bound systemd credential), never from the environment value or the image.

## Network & secrets

- **Inbound: Tailscale-only.** The router binds the `tailscale0` address; no LAN
  or public listener.
- **Egress: default-deny.** nftables is the authoritative floor; `api.anthropic.com`
  is reached via a dnsmasq-populated nftables set (the endpoint is on
  Anthropic-owned address space today, but IPs are never hardcoded). systemd
  `IPAddressDeny=any` on the slice is coarse defense-in-depth.
- **Secrets:** delivered via `systemd-creds` `LoadCredentialEncrypted=`, decrypted
  only into the consuming unit at `/run/credentials/<unit>/<id>` (tmpfs, noswap,
  mode 0400). TPM2-sealed on bare metal; host-key sealing in the qemu phase
  (vTPM unseal is unreliable — systemd #21747).

## Provenance

eBPF observe-only events stream over a BPF ring buffer to the Go collector,
which writes a **tamper-evident audit log**: each record is hash-chained
(`SHA-256(prev_hash || fields)`) and Ed25519-signed with a TPM-bound key; the
chain head is periodically anchored off-box over Tailscale to detect truncation.
The log lives on the persistent data partition (the rootfs is read-only in
production).

## Build sequencing

- **Prototype — Buildroot** (`x86_64`, qemu, CPU-only): validate the
  architecture fast. This is the v1 target.
- **Production — Yocto** (LTS) + **RAUC A/B** atomic updates, verity bundles,
  read-only rootfs, SPDX SBOM, measured boot + attestation, the CUDA/GPU build
  (Qwen3-14B), the BPF-LSM deny layer, and multi-agent orchestration.

## v1 scope

A Buildroot image that: boots to systemd; runs `llama-server` as a managed,
hardened service; runs the Go router with the routing rule and both backends
working; delivers the Anthropic key via a TPM-bound credential; enforces the
Tailscale-only / default-deny network boundary; and ships the eBPF observe-only
provenance collector with a fail-closed boot self-test. See
[decisions/0001](decisions/0001-foundational-architecture.md) for the milestone
breakdown (M0–M5).
