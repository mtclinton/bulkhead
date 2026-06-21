# bulkhead — pilot evaluation (software / VM)

Evaluate the appliance end-to-end **with no commissioned hardware**: one command boots the already-built
image under qemu + a software TPM and runs the live security proofs in critical-path order, then prints a
single **GO / NO-GO** verdict.

```sh
scripts/pilot-eval.sh            # the full pilot suite (+ the /dev/kvm arms if this host has KVM)
scripts/pilot-eval.sh --list     # show the plan without booting anything
```

It is honest about its limits: the qemu/swtpm pilot proves the security **mechanisms**; it does **not** prove
hardware-rooted trust. EK-rooted attestation and PCR-7 measured-boot sealing are marked `[HW-deferred]` and
need a commissioned TPM2 target (see [`COMMISSIONING.md`](./COMMISSIONING.md)).

## What it proves — the four legs

| Leg | `make` target | What a passing run demonstrates |
| --- | --- | --- |
| **BOOT** | `verify-hbd` | The hardened appliance boots with its security floor **live from cold boot** — the BPF-LSM action floor (E0+E2) is armed after a reboot, io_uring is compiled out, structural default-deny egress is up, the signed audit chains persist. |
| **SUBMIT + ISOLATE** | `verify-runsc-unit` | A real agent workload is launched the deployable way (`systemctl start bulkhead-agent-runsc@<inst>`) into the **gVisor default tier**: it runs to completion under host-surface collapse, both mediated legs work, egress is signed, the per-instance bundle is reaped. |
| **MEDIATE + SIGN** | `verify-confined-agent` | The agent's **only** ways out are the audited channels: an allowlisted fetch is mediated + signed into the chain; a non-allowlisted destination is **DENIED** and the deny is signed. |
| **INJECTION-SAFE** | `verify-quarantine` | The product thesis: a prompt injection in **fetched page content stays inert** — the plan's control flow is fixed *before* the untrusted bytes are read, so no privileged tool fires on attacker text. |
| **VERIFY OFF-BOX** | `verify-attest`, `verify-chain-monitor-live` | A fresh-nonce TPM-quoted attestation **binds the three audit-chain HEADs** (rewind / tamper fail closed), and the off-box `bulkhead-chain-monitor` **pins the HEAD off the box and catches a tail-truncation/rewind** within one interval. |

On a host with real `/dev/kvm` the script also runs three **optional** KVM-tier arms (non-root in-sandbox
hardening, `runsc --platform=kvm` host-surface collapse, the Firecracker hostile-tier jailer). They are
skipped cleanly on a KVM-less evaluator box and never gate the core verdict's availability.

## What it does NOT prove — the hardware wall

These need a target you commission (real TPM2 + enrolled Secure Boot keys + a real NIC) and are **out of the
software pilot** by design — run [`COMMISSIONING.md`](./COMMISSIONING.md) Phase 1–7 + `commission-check.py`
on the box for them:

- **EK-rooted attestation** — swtpm presents self-signed dev PKI, not a genuine manufacturer EK certificate,
  so the pilot proves the quote *mechanism* (nonce freshness, HEAD binding, no-rewind, tamper fail-closed) but
  not that it is rooted in real silicon.
- **PCR-7 measured-boot sealing** of the audit seed + MITM CA (`BULKHEAD_SEAL_KEY=tpm2`) — the qemu vTPM
  leaves the firmware PCRs zeroed, so the seal-to-hardware path has never executed.
- The **nftables default-deny floor on a real NIC** (qemu slirp masks direct-IP / DNS leakage), and the
  Firecracker hostile tier under a full commissioning.

## Prerequisites (eval host)

A built wic + the qemu/Yocto tooling — all present on the bulkhead build host:

- the production image at `yocto/build/tmp/deploy/images/qemux86-64/bulkhead-image-qemux86-64.rootfs.wic`
  (run `bitbake bulkhead-image` if absent), `qemu-system-x86_64`, `swtpm`, `runqemu` (via the Yocto
  `oe-init-build-env`), `ovmf`, and a host **Go toolchain** (the off-box monitor + collector are host-built);
- optional: `/dev/kvm` for the KVM-tier arms.

Each `verify-*` target boots its **own** qemu (minutes) and the suite runs them **sequentially** — budget
~30–60 min for the full run. To exercise a single leg, pass its target: `scripts/pilot-eval.sh verify-quarantine`.

## Reading the verdict

The run ends with a per-leg `PASS`/`FAIL` table and a single line: **`PILOT GO`** (every check on this host
passed) or **`PILOT NO-GO`** (with the failing checks named). The `[HW-deferred]` block is always printed so a
`GO` is never mistaken for hardware-rooted assurance. For the full readiness picture, see
[`PRODUCTION-READINESS.md`](./PRODUCTION-READINESS.md).
