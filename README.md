# bulkhead

**An agent appliance, built from the kernel up.** bulkhead is a Linux
distribution in which the isolation of an AI agent is an operating-system
guarantee — not a library bolted onto a general-purpose OS, and not a prompt
asking the model to behave.

The design starts from a blunt assumption: the agent is already compromised. A
prompt-injection-to-RCE chain has succeeded, and untrusted code is running inside
the sandbox. The interesting question is not "how do we keep the agent honest"
but "given a hostile agent, what boundary still stands between it and the host" —
and bulkhead's job is to make that boundary structural, kernel-enforced, and
small enough to audit.

> **Status: a working, hardened appliance under active development.** It boots to
> systemd, serves local inference and routed model calls, and confines agents on
> a kernel-enforced, fail-closed floor that the boot self-test refuses to come up
> without. Shipped and verified live (in qemu, under a software TPM): the BPF-LSM
> action-authorization layer and its TCB broker; a gVisor-based isolation
> substrate as the default agent tier; structural egress through a mediating
> proxy; the Dual-LLM model-routing quarantine; mediated multi-agent delegation;
> signed, hash-chained audit logs with TPM-quoted remote attestation; and a Yocto
> production image — verity rootfs, RAUC A/B atomic updates, anti-rollback. Every
> slice is proven live before the next one starts. The full design and its
> rationale live in [docs/architecture.md](docs/architecture.md), the
> [threat model](docs/threat-model.md), and 39 decision records under
> [docs/decisions/](docs/decisions/); a standing adversarial review tracks the
> gaps in [docs/security-reviews/](docs/security-reviews/).

## Why

On a normal Linux box an agent runs with the full authority of whoever launched
it: your shell, your keys, your network. bulkhead inverts that default and makes
confinement non-optional. Every agent runs inside a kernel-enforced sandbox it
cannot reach around; every privileged action it attempts is mediated by a small
trusted core, per agent, as policy the agent has no handle on; and every
security-relevant decision lands in a tamper-evident, signed log that a relying
party can verify off-box.

The bet is that isolation only becomes credible on a single-purpose appliance
with a small attack surface — so bulkhead is exactly that, not a daily driver.
The trusted computing base is a pinned kernel, a privileged collector, and a
caged broker; everything else is unprivileged and arranged so that breaking it
buys the attacker nothing the kernel hasn't already denied.

## What actually stands in the way

bulkhead is layered so that no single control is load-bearing on its own. Walking
outward from a compromised agent:

- **An isolation substrate, not just a namespace.** The default tier runs the
  agent under gVisor (`runsc`, Systrap platform, rootless): a reimplemented
  guest kernel that intercepts every syscall and collapses the host surface the
  agent can touch — a sandbox escape has to break the Sentry *and then* the host,
  not one CVE. The shared-kernel BPF-LSM tier (below) is kept for trusted
  workloads; a Firecracker microVM is the path for an explicitly hostile tier.
  `io_uring` is denied outright — it is a syscall-invisible I/O channel, so the
  substrate refuses it rather than trying to mediate it (ADR-0031/0032/0033).

- **Action authorization in the kernel, per agent.** A privileged collector owns
  the eBPF path and installs opt-in, fail-closed BPF-LSM hooks that deny, per
  agent cgroup: `bpf()` (protect the substrate the TCB rests on), `ptrace`
  (per-agent, finer than host-wide Yama), `socket_connect` against a per-agent
  egress-class manifest classified in-kernel from the destination, and privilege
  *gains* via `setuid`/`capset` (drops always allowed, raises denied). The
  manifest is installed by an exec-ordered `ExecStartPre` before the agent's
  payload can `connect()`, closing the install-vs-connect race without a sleep
  (ADR-0004 … ADR-0011).

- **A broker for the actions a human must gate.** A socket-activated,
  capability-caged broker authorizes sensitive requests with the caller's cgroup
  **kernel-attested** via `SO_PEERPIDFD` — never a field the agent can forge. It
  handles inter-agent egress delegation (`child = parent ∩ requested`, so
  authority can only ever narrow), a blocking human approval gate over a `0600`
  socket (uid-0 operator only), operator-driven expansion and in-place incident
  throttling, and a kernel-enforced one-shot privilege grant consumed atomically
  inside the BPF hook. A TCB-context garbage collector reclaims a dead agent's
  policy even when the agent's own cleanup is blocked (ADR-0006/0011/0012).

- **Egress that is structural, not advisory.** A confined agent runs in a
  no-route network namespace; its only way out is a UNIX socket to a host
  mediating proxy. The proxy resolves and connects on the host, denies internal
  address classes (SSRF, the metadata endpoint) on the *resolved* IP, and — for
  hosts marked for it — terminates TLS and inspects the flow, re-signing with an
  on-device CA the agent trusts. The DNS allowlist is kept as an advisory hint;
  the boundary is the namespace and the proxy, which is what makes it hold
  against a compromised agent (ADR-0034).

- **A model-routing quarantine, not a trusted prompt.** Untrusted fetched content
  never reaches a privileged tool. A planning model sees only the trusted task
  and emits a *static* plan; a deterministic, non-LLM interpreter executes it; a
  separate quarantined reader is the only thing that ingests untrusted bytes, has
  no tools, and whose reply is stored as data and never parsed as a directive.
  Control flow is fixed before a single untrusted byte is read (the CaMeL
  property), so an injection can steer *what a delegated child is told* but never
  *what it is allowed to do* (ADR-0036).

- **Each agent its own domain.** There is no shared trust pool and no direct
  agent-to-agent path; everything goes through mediated IPC that preserves
  authority. Delegation chains are bounded in depth and width, and a child's
  reach is transitively clamped to its parent's — narrow-never-widen all the way
  down, enforced by the broker and the kernel, not by the agents (ADR-0037).

- **Provenance you can verify off-box.** The collector, broker, proxy, and router
  each Ed25519-sign a hash-chained decision log that continues across boots;
  `verify-audit` recomputes the chain and is wired into the boot gate, so a
  tampered `/data` refuses the boot. The signing seed is a TPM-sealed credential
  on bare metal. A relying party can pull a TPM quote that binds the enforcing
  TCB's measured state to the chain HEADs and get a no-rewind verdict — the log
  it verifies is the one the box actually ran (ADR-0017 … ADR-0028).

## Model routing

The router is OpenAI-compatible and picks a backend per request under a
denial-of-wallet rule: a coarse, deterministic prompt-length gate is the *only*
path to a paid tier, and a client may force the free local tier but never the
paid one. Local inference (llama.cpp) is the default. The paid path is
provider-pluggable — Anthropic, OpenAI, Gemini — each a backend with its own
file-sourced key, a base pinned to that provider's exact host over HTTPS, and a
client that refuses redirects so a cross-host hop can't walk off with the key.
The vendor is chosen by model prefix *after* the length gate, never as a way to
reach the paid tier, and an optional per-minute cap bounds runaway spend. Keys
are TPM-bound credentials, per provider, never in the environment or an image.

## Build & run

You need a Linux build host. Neither the Buildroot tree nor the Yocto layers are
vendored; both are fetched at pinned revisions.

**Buildroot prototype** — fast, CPU-only, for iteration:

```sh
make buildroot     # fetch + checkout the pinned Buildroot tree
make defconfig     # load the bulkhead defconfig
make image         # build the appliance image -> output/images/
make run           # boot it in qemu
make verify        # assert the security floor is live in the booted guest
```

**Yocto production** — immutable verity rootfs with RAUC A/B atomic updates and
auto-rollback; a multi-hour build. See [yocto/README.md](yocto/README.md):

```sh
yocto/scripts/fetch-yocto.sh                  # poky + meta-oe + meta-rauc + meta-security @ scarthgap
source yocto/poky/oe-init-build-env yocto/build
bitbake bulkhead-image                        # -> wic image; signed RAUC bundle via bitbake bulkhead-bundle
```

The `make verify-*` targets boot the real image in qemu and assert a specific
guarantee end to end — the fail-closed floor, the egress boundary, cold-boot
attestation, sub-agent delegation, the quarantine, the gVisor substrate, the A/B
update and rollback. Nothing is called done until its target is green.

## Evaluate it (software pilot — no hardware required)

To assess the isolation, egress mediation, and signed-audit guarantees **without commissioning a
target**, build the Yocto wic (above) and run the one-command software pilot:

```sh
make pilot-eval          # boot the wic + run the live proofs in critical-path order -> one GO/NO-GO
make pilot-eval-list     # show the plan without booting anything
```

It boots the appliance under qemu + a software TPM and proves the path end to end — **hardened boot →
submit + isolate a real agent workload → mediated + signed egress → injection safety → off-box
verifiability** — then prints a plain-language **assurance summary** and a GO/NO-GO. It is honest about
its limits: EK-rooted attestation and PCR-7 measured-boot sealing need a real TPM2 and are marked
`[HW-deferred]`. Walkthrough: **[docs/PILOT-EVAL.md](docs/PILOT-EVAL.md)**.

- **Demo it live** (a narrated ~15-min walkthrough — containment, injection-safety, and an off-box
  tamper catch, each on the real booted image): **[docs/DEMO.md](docs/DEMO.md)**.
- **Watch it from off the box** (the continuous tamper-evident witness): stand up the off-box
  audit-chain monitor — **[deploy/chain-monitor.md](deploy/chain-monitor.md)**.
- **Take it to real hardware** (TPM-sealed boot, Secure Boot, real-NIC default-deny, A/B install):
  **[docs/COMMISSIONING.md](docs/COMMISSIONING.md)**.

## Source, secrets, and license

bulkhead is **[AGPL-3.0-only](LICENSE)**. Because it serves requests over a
network, the Corresponding Source for any running build — including the scripts
needed to reproduce the image — is offered to all network users under §13: a
running appliance exposes the offer at `GET /source` and an `X-Source-Code`
header, and the canonical source is this repository at the commit the image was
built from.

No credential, API key, or private key is **ever** committed here or baked into
an image. Secrets — provider keys, the RAUC signing key, the audit seed — are
supplied at runtime from a secret store or TPM-bound systemd credentials. A
gitleaks scan and a single-author / no-AI-attribution check run on every push and
pull request; `pre-commit install` wires the same checks locally.

Copyright (C) 2026 mtclinton.
