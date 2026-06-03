# bulkhead

**An agent appliance, built from the kernel up.** bulkhead is a Linux
distribution in which agent isolation, action authorization, and model routing
are system-level guarantees — not libraries bolted onto a general-purpose OS.

> **Status: working appliance, active development.** The v1 milestone (boots to
> systemd, local inference, kernel-enforced fail-closed floor, default-deny
> egress, Tailscale-only inbound) is complete and verified live in qemu, and the
> Yocto production distribution — immutable verity rootfs with RAUC A/B atomic
> updates and auto-rollback — builds, boots, and updates end-to-end. Work now
> centers on the flagship: **agent action authorization as an OS primitive**
> (the BPF-LSM enforce layer + a TCB broker mediating human-gated actions). See
> [docs/architecture.md](docs/architecture.md), the
> [threat model](docs/threat-model.md), and the
> [decision records](docs/decisions/) (ADR-0001 … ADR-0012) for the full design
> and rationale; every slice is verified live before the next.

## Why

On a normal Linux box an agent runs with the full authority of whoever launched
it. bulkhead makes confinement non-negotiable instead: every agent runs inside a
kernel-enforced sandbox, every privileged action is explicitly authorized, and
every security-relevant decision is recorded in a tamper-evident, signed log.
The defensible angle is security — a hardened agent appliance with a small,
auditable trusted computing base.

## Architecture, in one paragraph

A single pinned kernel provides the security substrate: cgroup v2, namespaces,
seccomp, Landlock, and BPF-LSM. Enforcement is **layered and fail-closed** — a
seccomp + Landlock + dropped-capability + namespace floor is applied at process
launch, so an agent *cannot* run unconfined, and a boot-time self-test gates the
services behind it. On top of that floor a privileged **collector** owns the
eBPF path: high-fidelity provenance plus an **opt-in BPF-LSM enforce layer**, and
a signed, hash-chained audit log. A managed local inference service (llama.cpp)
and a Go request router run as unprivileged services. Inbound is Tailscale-only;
egress is default-deny with a DNS-driven allowlist. Secrets are delivered at
runtime via TPM-bound systemd credentials and never live in the repo or an
image. The prototype is built with Buildroot; the production distribution is
built with Yocto and ships RAUC A/B atomic updates over a verity rootfs. Full
detail in [docs/architecture.md](docs/architecture.md).

## Agent action authorization (the flagship)

Beyond the launch-time floor, bulkhead authorizes *what a running agent may do*
in the kernel, per agent, as policy the agent cannot reach:

- **BPF-LSM enforce (E0–E3).** Opt-in, default-observe, fail-open, TCB-exempt
  LSM hooks deny, per agent cgroup: `bpf()` (protect the substrate), `ptrace`
  (per-agent, finer than host-wide Yama), `socket_connect` (a per-agent egress
  **class** manifest classified in-kernel from the connect address), and
  privilege gains via `setuid`/`capset` (allow drops, deny raises).
- **Per-agent jails.** Each agent is a systemd template instance in its own
  cgroup; an exec-ordered `ExecStartPre` installs the agent's egress manifest
  *before* its payload can `connect()`, closing the manifest-vs-connect race
  without a sleep.
- **A TCB broker for gated actions.** A small, socket-activated, capability-caged
  broker authorizes sensitive actions with the requester's cgroup
  **kernel-attested** (`SO_PEERPIDFD`) — never a forgeable request field:
  inter-agent egress **delegation** (`child = parent ∩ requested`,
  narrow-never-widen), a **human approval-gate** (block for a uid-0 operator
  decision over a `0600` socket), operator-approved egress **expansion** and
  operator-initiated **narrow** (in-place incident throttle), and a
  **kernel-enforced one-shot E1/E3 privilege grant** (a human-approved, single-use
  exception consumed atomically in the BPF hook). A TCB-context garbage collector
  reclaims a dead agent's policy even when the agent's own cleanup is blocked.
- **Signed, verifiable audit.** The collector and broker each Ed25519-sign a
  hash-chained decision log; `bulkhead-collector verify-audit` recomputes and
  checks the chain, wired into the boot gate so a tampered chain refuses the
  boot. The signing key is a TPM-sealed (bare metal) / persistent (VM) credential.

Every item above is implemented and verified live in qemu — see ADR-0004 through
ADR-0012.

## Model routing

The router is OpenAI-compatible and chooses the backend per request under a
**denial-of-wallet** rule: a coarse, deterministic prompt-length gate is the
*only* path to a paid tier (a client may force the free local tier but never the
paid one).

1. **Local inference** (llama.cpp) — tokenless, for high-volume and
   privacy-sensitive work; the default tier.
2. **Paid API — provider-pluggable.** Anthropic (default), OpenAI, and Gemini,
   each a backend with its own file-sourced key, host-pinned base, and
   no-redirect client; the vendor is chosen by model prefix *after* the
   length gate, never as a way to force the paid tier.

Keys are file/credential-sourced (TPM-bound), per provider, never in env or an
image; the egress floor's DNS allowlist gains a set per provider.

## Build & run

Requires a Linux build host. Neither the Buildroot tree nor the Yocto layers are
vendored; both are fetched at pinned revisions.

**Buildroot prototype** (fast, CPU-only, for iteration):

```sh
make buildroot     # fetch + checkout the pinned Buildroot tree
make defconfig     # load the bulkhead defconfig
make image         # build the appliance image -> output/images/
make run           # boot it in qemu
make verify        # assert the security floor is live in the booted guest
```

**Yocto production** (immutable verity rootfs + RAUC A/B updates; a multi-hour
build) — see [yocto/README.md](yocto/README.md) for the full flow:

```sh
yocto/scripts/fetch-yocto.sh                       # poky + meta-oe + meta-rauc + meta-security @ scarthgap
source yocto/poky/oe-init-build-env yocto/build
bitbake bulkhead-image                             # -> wic image; signed RAUC bundle via bitbake bulkhead-bundle
```

## Source code offer (AGPL-3.0 §13)

bulkhead is licensed under **AGPL-3.0-only**. Because it serves requests over a
network, the Corresponding Source for any running build — including the build
scripts needed to reproduce the image — is offered to all network users. A
running appliance exposes the offer at `GET /source` and an `X-Source-Code`
response header; the canonical source is this repository at the commit the image
was built from.

## Secrets policy

No credential, API key, or private key is **ever** committed to this repository
or baked into an image. Secrets are supplied at runtime from a secret store or
TPM-bound systemd credentials (provider keys, the RAUC signing key, the audit
seed). A [gitleaks](https://github.com/gitleaks/gitleaks) scan and a
single-author/no-AI-attribution check run on every push and pull request; a
local pre-commit hook is available (`pre-commit install`).

## License

[AGPL-3.0-only](LICENSE). Copyright (C) 2026 mtclinton.
