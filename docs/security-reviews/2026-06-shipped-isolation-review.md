# Security review — shipped agent-isolation architecture (2026-06)

Status: 3 confirmed wiring-gap findings (R1, R2, R4) fixed + live-verified; R3 **reclassified** by
its own live counterfactual from a MED DoS to a defense-in-depth hardening (the DoS was not
exploitable in the rootless config — see below); R5 accepted-and-deferred.

## Scope

An adversarial review of bulkhead's **already-shipped** security architecture — not the
roadmap, but the code on `main`:

- the egress boundary (ADR-0034: structural confinement + the mediating proxy + the signed chain),
- broker-mediated delegation (ADR-0006/0015/0037: narrowed children, depth/width caps, attested authority),
- the gVisor substrate (ADR-0031: the default tier, minimal-rootfs OCI bundle, mediated UDS legs).

The review looked for one specific class of bug: a **wiring gap** — a guarantee the design
intends, that turns out to be enforced at a *softer* layer than the threat model assumes. The
fix in every case is to move the enforcement down to the hard layer a compromised agent cannot
reach.

## Cross-cutting theme

Each finding had the same shape — an enforcement living one layer too high:

| Found enforcing at (soft) | Should enforce at (hard) |
|---|---|
| systemd `Before=` ordering (does not propagate failure) | systemd `Requires=` (R1) |
| an in-jail `Environment=` flag (a compromised agent ignores it) | the TCB, keyed on kernel attestation (R2) |
| an implicit "best effort, else pass through" | fail closed (R4) |

A compromised agent or a tampered `/data` is *assumed* by the threat model; a guarantee that
only holds when neither is true is not a guarantee. These three close that gap. (R3 looked like a
fourth — an `rw` bind-mount default — but its live counterfactual showed the protection was already
hard, at the kernel's user-namespace DAC; see R3 below.)

## Findings

### R1 [HIGH] — the untrusted-web chokepoint did not honor the fail-closed audit gate

The egress proxy is the single mediated path for untrusted web. The boot self-test gates the
TCB closed on a forged/gapped `/data` audit chain — but the proxy was only `Before=`-ordered
after the verifier, and `Before=` does **not** propagate failure. A tampered chain therefore
refused the collector (TCB) yet still granted the agents web egress: the loudest possible
boundary, silently open.

Fix: the proxy now `Requires=bulkhead-selftest.service` (which on Yocto `Requires=` the chain
verifier), mirroring the trusted router leg. A forged chain refuses the proxy **and**
transitively every confined/runsc agent that `Requires=` it.

Fix: `d80487d`. Verify: `make verify-egress-gate` — single-boot tamper test; a forged record
makes `verify-audit` fail, `systemctl start` of the proxy is refused, and a confined agent
cannot start. (The destructive test forges into `/data`, so its harness runs the VM under
`snapshot`; `ac67986`.)

### R2 [HIGH] — a delegated child's egress-widen cap lived in the jail, not the TCB

A broker-minted delegated child must never widen its egress past its delegation root (the
grandchild ⊆ child ⊆ parent lifetime invariant the depth/width caps enforce). But the broker's
`EXPAND` handler never checked delegation generation: `NO_EXPAND` was only an `Environment=`
flag inside the **untrusted** agent runtime. A compromised child could `exec
bulkhead-collector expand` (or write `EXPAND` to the broker socket) directly, bypassing its own
runtime, and the broker would mint a wider mask.

Fix: the broker (TCB) now refuses `EXPAND` from any child whose **kernel-attested** cgroup path
has delegation generation > 0 — the same un-spoofable signal the depth cap already trusts.
Top-level agents (gen 0) still `EXPAND` with operator approval.

Fix: `bb70990`. Verify: `TestExpandRefusedForDelegatedChild` (broker unit) + `make
verify-agent-orch` (full delegation chain + depth cap, no regression). The attestation that
yields the correct generation is itself live-proven by the depth-cap arm (`ARM DEPTHCAP`).

### R3 [MED → reclassified to defense-in-depth] — the substrate's mediated UDS legs were writable

A gVisor-tier agent reaches the host proxy/router through two UDS legs bind-mounted from
`/run/bulkhead-{egress,router}`. They were mounted `rw`. The finding's **premise** was that a
sandboxed agent could therefore `unlink`/replace the shared `egress.sock`, removing every other
tier's only way out.

Fix: mount both legs `ro`. `connect()` still works (the agent keeps its mediated egress); the
agent has no business writing the leg dir.

**Live verification reclassified this from a MED DoS to a defense-in-depth hardening.** The `rw`
counterfactual showed the cross-tier write is refused **even with the leg mounted `rw`** — so the
load-bearing control is the **rootless user-namespace DAC**: runsc's gofer maps to host-nobody for
the proxy-owned, mode-`0755` leg dir and cannot write it regardless of the mount flag. The DoS was
therefore **not exploitable** in the rootless config. The `ro` mount is genuine least-privilege and
becomes load-bearing only for a non-rootless / root-gofer tier (where the userns remap would not
apply), so it is kept as defense-in-depth — not reverted.

Fix: `d4b08a0` (kept). Verify: `make verify-runsc-run` — the agent loop reaches HTTP 200 through
the `ro` leg; `probe-romount` shows `unlink`/`create` REFUSED; the `rw` counterfactual shows the
write *still* REFUSED, attributing the protection to the userns DAC (`8cb8f1a`). gVisor surfaces
the refusal as `EACCES`/`EPERM`, not Linux's `EROFS`.

This is the point of an adversarial counterfactual: it falsified the finding's premise before the
fix could ship on a false rationale, and it pinned down *which* layer actually holds the line.

### R4 [MED] — content-inspection failed *open* when it couldn't terminate

An operator marks a host `inspect` to see inside it (TLS-terminate + content-inspect). But the
proxy only terminated when a re-signing CA was loaded **and** the port was a TLS port; every
other case — crucially a CA that failed to load — fell through to an opaque passthrough splice.
A missing CA therefore silently downgraded **every** inspect host to uninspected egress while
the operator believed they were inspected.

Fix: decide the disposition **before** dialing. An inspect host the proxy cannot terminate (no
CA, or a non-TLS port) is now **denied** — the chain signs a single deny
(reason=`inspect-unavailable`) and the upstream is never reached, rather than dialing out and
signing a misleading "allow". `inspect` now means *inspect or refuse*; a host meant to ride
opaque must be marked `pinned`/passthrough.

Fix: `30e29b9`. Verify: `TestHandleConnInspectUnavailableDenies` (proxy unit: single deny,
upstream never dialed) + `make verify-egress-mitm` ARM 3 (an inspect host on a non-TLS port is
refused, no inspect/passthrough record written).

## R5 [LOW] — accepted and deferred

The control-plane (action-authorization) chain records **after** the map write, so an
audit-append failure there can leave a state change unrecorded — the inverse of the egress
proxy's record-**before**-act discipline. Severity is LOW (the control chain is internal, not a
boundary an untrusted agent reaches) and the fix touches the collector's hot path, so it is
deferred to a dedicated change with owner sign-off rather than bundled into this review.

## Verification posture

Every R1–R4 change is a single self-contained commit + recipe re-pin, with `main` green at each
checkpoint, and is **live-verified** on the `qemux86-64` wic image (not merely unit-tested) — each
by a tamper/adversarial arm that fails the boundary it concerns. The live checks are the
`verify-egress-gate` (R1), `verify-agent-orch` (R2), `verify-runsc-run` (R3), and
`verify-egress-mitm` (R4) targets. R3's live arm went further than confirm-the-fix: its `rw`
counterfactual *reclassified the finding*, which is the intended outcome of building the
counterfactual rather than asserting the fix's rationale.
