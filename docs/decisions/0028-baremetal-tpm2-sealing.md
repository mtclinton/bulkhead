# ADR-0028: bare-metal TPM2 sealing — a single-switch production wiring

Status: Accepted
Date: 2026-06-06
Relates to: ADR-0008 (measured boot + the TPM-sealed audit seed; defines the `plain` vs `tpm2` key
modes and the seal binary), ADR-0027 (the router's signed routing-decision chain — a NEW audit-seed
consumer), ADR-0001 #12 / systemd #21747 (qemu vTPM `LoadCredentialEncrypted` is non-deterministically
flaky, which is why the VM ships `plain`). Closes the "manual, error-prone bare-metal switch" gap.

## Context

ADR-0008 implemented both audit-seed key modes — `plain` (a plaintext seed on `/data`, the reliable
VM/dev default) and `tpm2` (a hardware-sealed `/data/bulkhead/audit-seed.cred`, PCR 7) — and proved the
tpm2 seal MECHANISM live (seal → unseal → survive reboot → fail-close on PCR-7 perturbation). But it left
the bare-metal switch as a hand-edit: ADR-0008 literally says "set `BULKHEAD_SEAL_KEY=tpm2` AND switch
the collector/broker drop-ins to `LoadCredentialEncrypted`". That is fragile on three counts:

1. **It is per-file and easy to get partially wrong.** The seed has FOUR consumers, not two: the
   collector, the broker, the router (ADR-0027, which did not exist when ADR-0008 was written), and the
   `bulkhead-verify-audit` boot gate. Each loads the seed independently. Miss ONE and that unit either
   reads a non-existent plaintext seed (fail-closed → bricked boot) or, worse, a stale seed — a silent
   split-brain. The audit chain is fail-closed by design, so a partial switch bricks the appliance.
2. **There was no single source of truth** for "this image is a bare-metal tpm2 build."
3. **The plaintext VM path must stay byte-for-byte intact** — qemu's vTPM makes PID1
   `LoadCredentialEncrypted` flaky (ADR-0001 #12), so dev/CI builds must not accidentally get tpm2.

## Decision

**One build flag flips the whole topology, coherently.** A `BULKHEAD_SEAL_KEY` variable (default
`plain`) selects the audit-seed key delivery at image-build time. `bulkhead-units`'s `do_install`
branches on it; `do_install[vardeps] += "BULKHEAD_SEAL_KEY"` so a flag change re-runs the install.

- **`plain` (default, VM/dev) — installs NOTHING new.** The plaintext-seed path (seal writes
  `/data/bulkhead/audit-seed`, consumers carry `LoadCredential=audit-seed:…`) is untouched.
- **`tpm2` (bare metal) — installs five override drop-ins** from two source files:
  - `seal-tpm2-mode.conf` → `bulkhead-seal-audit-key.service.d/20-tpm2.conf`: overrides the base unit's
    `Environment=BULKHEAD_SEAL_KEY=plain` (a keyed directive — the later value wins) so first boot
    hardware-seals `audit-seed.cred` (`systemd-creds --with-key=tpm2 --tpm2-pcrs=7`).
  - `audit-cred-tpm2.conf` → `<unit>.service.d/20-audit-cred-tpm2.conf` for ALL FOUR consumers
    (collector, broker, router, verify-audit). One identical file (same `.cred`, same landing path):
    `LoadCredential=` (the empty string RESETS the base unit's plaintext list directive) then
    `LoadCredentialEncrypted=audit-seed:/data/bulkhead/audit-seed.cred`. systemd unseals it into
    `$CREDENTIALS_DIRECTORY/audit-seed` — exactly where `loadSigningKey`/`verify-audit` already read, so
    there is **ZERO Go change**. The `20-` prefix sorts after every base credential drop-in (`10-`/`12-`).

Set `BULKHEAD_SEAL_KEY = "tpm2"` in `local.conf` for a bare-metal release (documented in
`local.conf.production.sample`). Encrypted at rest, unsealable only on the expected boot;
`LoadCredentialEncrypted` of an undecryptable cred fail-closes the unit, reinforcing
`BULKHEAD_REQUIRE_SEALED_KEY=1`.

## Verification

- **The build flag is coherent (verified).** `bitbake -c install` with `BULKHEAD_SEAL_KEY=tpm2` installs
  all five drop-ins in the correct `.d` dirs with the correct `LoadCredential=` reset +
  `LoadCredentialEncrypted` content; the default `plain` build installs ZERO tpm2 drop-ins (the VM path is
  unchanged). Both confirmed by inspecting the recipe's image staging dir.
- **The tpm2 seal MECHANISM re-proven live (the foundation the wiring rests on).** Under swtpm via the
  `systemd-creds` CLI (`scripts/_tpm2_spike.py`, two boots): systemd is built `+TPM2 +OPENSSL`; a seed
  seals to a PCR-7 cred, unseals same-boot to 32 bytes, unseals IDENTICALLY after a reboot (PCR 7 is
  stable), and the unseal FAILS CLOSED once PCR 7 is perturbed (`tpm2_pcrextend 7`). This is the CLI path,
  which ADR-0008 found reliable.
- **Honest limit — live PID1 use is bare-metal-only.** As ADR-0008 documented in detail, PID1
  `LoadCredentialEncrypted` of a tpm2 cred is non-deterministically flaky under qemu's vTPM (EPROTO
  `243/CREDENTIALS`, systemd #21747), and firmware measured boot does not populate PCRs under qemu/OVMF
  (the kernel does `TPM2_Startup(CLEAR)`). So the END-TO-END tpm2 boot (the five overrides actually
  unsealing at unit start) is verified only on bare-metal hardware. This slice makes that path a single,
  correct, fail-closed switch — it does not (and cannot here) re-litigate the qemu vTPM flakiness.

## Seam

- **Secure Boot key enrollment** makes PCR 7 meaningful (it attests "booted under our SB key"). Enrolling
  the SB keys + signing the bootchain is the bare-metal provisioning step that turns the coarse PCR-7
  binding into a real attestation anchor; it is out of scope here (no build host can enroll a device's TPM).
- **PCR 7 is coarse by design** (update-safe across RAUC A/B; ADR-0008). Tightening toward a signed PCR-11
  kernel-phase policy is the later step.
- **The same `LoadCredentialEncrypted` pattern** now generalizes to the other at-rest secrets (Tailscale
  authkey, provider API keys, the RAUC signing key) — a clean follow-on.
