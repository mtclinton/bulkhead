# ADR-0008: Measured boot + TPM-sealed audit key

Status: Accepted
Date: 2026-06-01
Relates to: ADR-0001 #12 (vTPM unseal unreliable / systemd #21747 → host key in the qemu
phase), ADR-0004 (BPF-LSM enforce + the Ed25519 audit chain), ADR-0007 (broker decision
chain). Threat model: "TPM-bound systemd-creds secrets", "measured boot + attestation".

## Context

The entire authorization + audit edifice (enforce E0–E3, the collector provenance chain,
the broker decision chain) rested on an unverified foundation: the audit-log signing key
was **ephemeral** (`loadSigningKey` generated a throwaway Ed25519 key per boot when no
credential was present). So the "tamper-evident signed log" was only as trustworthy as an
unattested boot — an attacker who modified the rootfs or swapped the BPF object got a
fresh valid-looking key and the chain still "verified." This ADR anchors the signing key
to the hardware TPM.

## Decision

**The audit signing seed is a TPM-sealed credential.** A first-boot oneshot
(`bulkhead-seal-audit-key.service`) generates 32 random bytes and seals them with
`systemd-creds encrypt --name=audit-seed --with-key=tpm2 --tpm2-pcrs=7` to
`/data/bulkhead/audit-seed.cred` (ciphertext only; the plaintext is piped, never written).
The collector and broker carry `LoadCredentialEncrypted=audit-seed:…`, so systemd unseals
it via the TPM into `$CREDENTIALS_DIRECTORY/audit-seed` — exactly where `loadSigningKey`
already reads it (**zero happy-path Go change**). Both share one sealed seed → one stable
audit identity across reboots.

**Why on-device first-boot sealing (not build-time):** tpm2 sealing binds to the
*device's own* TPM, so a build host cannot seal to it; the seal must happen on the device.
Idempotent — sealed once, later boots only unseal.

**PCR 7 only.** The seal binds to PCR 7 (Secure Boot state), which is **stable across RAUC
A/B updates and rollback** — a new same-key-signed kernel/rootfs changes PCR 8/9 (cmdline,
kernel hash) but not PCR 7. Sealing to PCR 4/8/9 would make the audit key permanently
unsealable after the first update — the brick trap, avoided by construction.

**Fail-closed, two layers.** (1) `LoadCredentialEncrypted` of an undecryptable cred makes
systemd refuse to start the unit; the broker `Requires=` the collector, and the selftest
gate keeps everything else down. (2) A ~6-line `BULKHEAD_REQUIRE_SEALED_KEY=1` guard in
`loadSigningKey` refuses to fall back to an ephemeral key on the appliance (the dev/
Buildroot path, env unset, keeps ephemeral-with-warning so non-TPM smoke tests run).

**Measured-boot infrastructure** (OVMF `TPM_ENABLE=TRUE` via `MACHINE_FEATURES += tpm2`,
the GRUB `tpm` module via a bbappend, kernel `CONFIG_TCG_TPM/TIS/CRB`, `systemd-pcrphase`
via `PACKAGECONFIG:pn-systemd += "tpm2 openssl"`) is in place so PCRs 0–11 are extended on
hardware that drives the TPM correctly.

## Verification (and the honest qemu/bare-metal split)

A spike-first gate (per ADR-0001 #12) ran the qemu/swtpm/OVMF path. Findings, proven live:

- **systemd-creds encrypted credentials need `openssl`, not just `tpm2`.** Without it
  systemd is built `-OPENSSL` and reports "Support for encrypted credentials not
  available." Adding `openssl` to the systemd PACKAGECONFIG fixed it (`+OPENSSL +TPM2`).
- **tpm2 sealing works and is what we ship:** `systemd-creds --with-key=tpm2 --tpm2-pcrs=7`
  seals, same-boot unseals, **survives a reboot** (stable key, not ephemeral), and
  **fail-closes** when PCR 7 is perturbed (`tpm2_pcrextend 7` → unseal fails). All proven
  in qemu with swtpm (`yocto/scripts/run-qemu-tpm.sh`).
- **Live firmware measured boot does NOT work under qemu/OVMF/swtpm** — the kernel logs
  `TPM error (256) … starting up the TPM manually`, doing `TPM2_Startup(CLEAR)` which wipes
  any firmware/GRUB measurements, so PCRs 0–9 read 0. This is exactly the systemd #21747 /
  ADR-0001 #12 limitation. **Consequence:** in the VM phase the PCR-7 *binding* is
  mechanically demonstrated (sealing + tamper-fail), but PCR 7 carries no real measurement;
  **real SB-measured PCR 7 — and Secure Boot key enrollment that makes it meaningful — is a
  bare-metal task.** The infrastructure is staged and correct; only the live measurement is
  deferred. This is stated plainly rather than claimed.

So this slice delivers, today and provably: a **hardware-anchored, non-ephemeral, fail-
closed** audit signing key. It stages — but does not yet prove on qemu — boot measurement
into PCRs.

## Honest weaknesses / deferrals

- PCR 7 is coarse (attests "booted under our Secure Boot key," not "exactly this kernel");
  that coarseness is what makes it update-safe. Tightening via a signed PCR-11 policy is a
  clean later step toward attestation.
- vTPM measured boot in qemu (firmware PCR population) — bare-metal only.
- The sealed key still protects only at-rest / wrong-boot; a live post-unseal in-TCB
  compromise can read it from the credential tmpfs — that remains the eBPF/LSM floor's job.

## Seams (built toward, not built)

- **Remote attestation:** a TPM AK + `tpm2_quote` over the now-measured PCRs, verified by
  a remote/operator — reuses this TPM bring-up + the off-repo signing posture.
- **Seal other secrets** (Tailscale authkey, Anthropic key, RAUC) via the identical
  `LoadCredentialEncrypted` pattern.
- **PCR-gated RAUC rollback** and a signed PCR-11 policy for kernel-phase assurance.
