# bulkhead

**An agent appliance, built from the kernel up.** bulkhead is a Linux
distribution in which agent isolation, action authorization, and model routing
are system-level guarantees — not libraries bolted onto a general-purpose OS.

> **Status: early development.** Milestone **v1** — a Buildroot image that boots
> to a minimal systemd userland, runs a local inference server as a managed
> service, and routes each request to either a local model or the Anthropic API
> under a kernel-enforced, fail-closed security floor — is in progress. See
> [docs/architecture.md](docs/architecture.md) and the
> [milestone plan](docs/decisions/0001-foundational-architecture.md).

## Why

On a normal Linux box an agent runs with the full authority of whoever launched
it. bulkhead makes confinement non-negotiable instead: every agent runs inside a
kernel-enforced sandbox, every capability is explicitly granted, and every
security-relevant action is recorded in a tamper-evident provenance log. The
defensible angle is security — a hardened agent appliance with a small,
auditable trusted computing base.

## Architecture, in one paragraph

A single pinned kernel provides the security substrate: cgroup v2, namespaces,
seccomp, Landlock, and BPF-LSM. Enforcement is **layered and fail-closed** —
seccomp + Landlock + dropped capabilities + network namespaces are applied at
process launch, so an agent *cannot* run unconfined, while eBPF provides
high-fidelity, **observe-only** provenance on top. A managed local inference
service (llama.cpp) and a Go request router run as unprivileged services; a
separate privileged collector owns the eBPF provenance path. Inbound is
Tailscale-only; egress is default-deny. Secrets are delivered at runtime via
TPM-bound systemd credentials and never live in the repo or an image. The
prototype is built with Buildroot; the production distribution targets Yocto
with RAUC A/B atomic updates. Full detail in
[docs/architecture.md](docs/architecture.md).

## Model routing

Three distinct backends, each its own route with its own auth and policy:

1. **Local inference** (llama.cpp) — tokenless, for high-volume and
   privacy-sensitive work.
2. **Anthropic API** — metered, for programmatic Claude calls from system
   services.
3. **Interactive Claude Code** (optional, Max subscription) — for human-driven
   agent work, *not* a backend for system traffic.

## Build & run

Requires a Linux build host. The Buildroot tree is **not vendored**; it is
fetched at a pinned tag by `scripts/fetch-buildroot.sh`.

```sh
make buildroot     # fetch + checkout the pinned Buildroot tree
make defconfig     # load the bulkhead defconfig into Buildroot
make image         # build the appliance image -> output/images/
make run           # boot the image in qemu (CPU-only)
make verify        # assert the security floor is live in the booted guest
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
or baked into an image. Secrets are supplied from the environment or a secret
store at runtime (the Anthropic key via TPM-bound systemd credentials). A
[gitleaks](https://github.com/gitleaks/gitleaks) scan runs on every push and
pull request, and a local pre-commit hook is available (`pre-commit install`).

## License

[AGPL-3.0-only](LICENSE). Copyright (C) 2026 mtclinton.
