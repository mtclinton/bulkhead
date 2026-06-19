<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# bulkhead — Bare-Metal Commissioning Runbook

> Turnkey bring-up of a bulkhead appliance on **real hardware**. Every step cites a real command/config/unit.
> This is the step that **first proves the build-verified bare-metal path on physical hardware** — the qemu
> verify suite has no nested KVM, an unreliable vTPM, and slirp networking, so TPM2-sealed boot, the FC microVM
> on real `/dev/kvm`, EK-rooted attestation, and the real-NIC egress floor have never run until now.
> Cross-reference: `docs/PRODUCTION-READINESS.md` (the gates this closes) and `docs/INCIDENT-RESPONSE.md`.

## Prerequisites

- **Hardware:** x86-64; a discrete **TPM 2.0**; **UEFI with Secure Boot** (custom-key enrollment); `/dev/kvm`
  (for the runsc-KVM + Firecracker tiers); a NIC; storage ≥ ~3 GB for the GPT A/B layout.
- **Off-repo signing material (you provision):** a **RAUC device CA** (`ca.cert.pem`) + a release signer whose
  private key ideally lives in an HSM/PKCS#11 (`*.pem` are `.gitignore`d and never in the repo); your **UEFI
  Secure Boot keys** (PK/KEK/db).
- A management host with the `bulkhead-collector` + `bulkhead-chain-monitor` binaries built from the same
  release (`cd src/<m> && CGO_ENABLED=0 go build .`) for off-box verify/monitor.

---

## ⚠ Three critical divergences (read first — they will bite)

bulkhead is built and CI'd for `MACHINE=qemux86-64`. Running that wic on real hardware is the *intended* path
but is build-verified only. Address these before/at flash time:

1. **No bare-metal MACHINE / BSP.** Every build is `qemux86-64` (`yocto/build/conf/local.conf`); there is no
   `genericx86-64` machine conf. The qemux86-64 wic boots generic x86-64 UEFI hardware in practice, but you
   own validating drivers/firmware for your board.
2. **The slot + `/data` device paths are hardcoded to `/dev/sda`.** `meta-bulkhead/recipes-core/rauc/files/
   qemux86-64/system.conf` pins `device=/dev/sda3` (root_a), `/dev/sda4` (root_b), `/dev/sda5`; `/data` is
   `/dev/sda6` (the `*-data.conf` drop-ins). On **NVMe (`/dev/nvme0n1p*`) or virtio (`/dev/vda*`)** these are
   wrong → RAUC slot detection and the `/data` mount fail. Provide a `system.conf` + data drop-ins matching
   your storage's device naming, or ensure the target enumerates the boot disk as `/dev/sda`.
3. **No Secure Boot signing infra is in-tree.** `grep` finds no `sbsign`/shim/MOK/db tooling in `meta-bulkhead`
   (ADR-0008 flags this). You must enroll PK/KEK/db and sign GRUB+kernel yourself (Phase 3) — until then
   PCR 7 reflects setup-mode and the seal is not bound to a meaningful boot state.

---

## Phase 1 — Build the TPM2-sealed production image

```sh
cd yocto && source poky/oe-init-build-env build
bitbake-layers show-layers      # expect: meta-bulkhead, meta-rauc, meta-rauc-qemux86, meta-security, meta-tpm

# 1a. Switch to the PRODUCTION config (locked root, no ssh/debug-tweaks, real RAUC CA).
cp ../conf/local.conf.production.sample conf/local.conf
#   then edit: BULKHEAD_RAUC_KEYDIR=/etc/bulkhead/rauc (your CA dir), RAUC_KEY_FILE (PKCS#11 URI), and add:
echo 'BULKHEAD_SEAL_KEY = "tpm2"' >> conf/local.conf      # the one flag that flips the whole audit-seed posture

# 1b. The build FAILS CLOSED on misconfig (bulkhead-image.bb:77-99): bb.fatal if BULKHEAD_PRODUCTION=1 and any
#     debug-tweaks/ssh/empty-root leaked in, or if ${BULKHEAD_RAUC_KEYDIR}/ca.cert.pem is not a real CA.
openssl x509 -noout -subject -in $BULKHEAD_RAUC_KEYDIR/ca.cert.pem   # must print YOUR CA, not meta-rauc's dummy

bitbake bulkhead-image
ls -l tmp/deploy/images/qemux86-64/bulkhead-image-qemux86-64.rootfs.wic   # the ~2.6 GB A/B GPT disk
bitbake bulkhead-bundle   # the RAUC verity update bundle for field re-flash; `rauc info <bundle>.raucb` verifies it
```

`BULKHEAD_SEAL_KEY=tpm2` (`bulkhead-units_0.1.0.bb:151-175`) installs five drop-ins: `LoadCredentialEncrypted=
audit-seed` on collector/broker/router/egress-proxy/verify-audit, plus the seal + provision-mitm-ca services
in tpm2 mode (seal the seed **and** the ADR-0034 re-signing CA to **PCR 7**). The default `plain` installs none
of this (the qemu path is unchanged, because qemu's vTPM makes PID1 `LoadCredentialEncrypted` non-deterministic).

The wic GPT layout (`meta-bulkhead/wic/bulkhead-grub-efi.wks`): `boot`(vfat EFI) · `grubenv`(vfat) ·
`rescue`/`root_a`/`root_b`(ext4 A/B+rescue) · `data`(ext4, survives A/B). Inspect with `wic ls <wic>`.

## Phase 2 — Flash the wic to the target

```sh
# DESTROYS the target disk. Confirm /dev/<DISK> is the appliance disk.
sudo bmaptool copy tmp/deploy/images/qemux86-64/bulkhead-image-qemux86-64.rootfs.wic /dev/<DISK>
#   or: sudo dd if=<wic> of=/dev/<DISK> bs=64M oflag=direct status=progress; sync
sudo sgdisk -p /dev/<DISK>   # expect 6 partitions: boot grubenv rescue root_a root_b data
```

## Phase 3 — Enroll Secure Boot keys + sign the boot chain (operator work — not in-tree)

Generate PK/KEK/db, enroll them in UEFI setup mode, and `sbsign` GRUB + the kernel with your db key (use your
org's standard SB tooling — bulkhead ships none). With Secure Boot **on**, firmware now measures the boot chain
into **PCR 7**; the audit seed seals to PCR 7 because it is stable across RAUC A/B (the rootfs hash is not).
Until this is done the seal is not bound to a meaningful boot state.

## Phase 4 — First boot + verify the PCR-7 seal

```sh
tpm2_pcrread sha256:0,1,2,3,4,5,6,7   # PCRs 0-7 NON-zero (firmware-populated); PCR 7 = your SB-key state

# the seed + the re-signing CA sealed at first boot (ciphertext only on /data; no plaintext):
systemctl is-active bulkhead-seal-audit-key.service bulkhead-provision-mitm-ca.service
test -s /data/bulkhead/audit-seed.cred && ! test -e /data/bulkhead/audit-seed
systemd-creds decrypt --name=audit-seed /data/bulkhead/audit-seed.cred - | wc -c   # 32 (the Ed25519 seed)
test -s /data/bulkhead/mitm-ca/ca.key.cred && ! test -e /data/bulkhead/mitm-ca/ca.key

# every audit-seed consumer unseals at unit start and re-unseals identically across a COLD reboot:
for u in bulkhead-collector bulkhead-broker bulkhead-router bulkhead-egress-proxy; do systemctl is-active $u; done

# FAIL-CLOSED proof: perturb PCR 7 and a consumer must REFUSE to start (the seed no longer unseals).
tpm2_pcrextend 7:sha256=$(printf tamper | sha256sum | cut -c1-64)
systemctl restart bulkhead-collector; systemctl is-failed bulkhead-collector   # => failed
#   (reboot to restore the real PCR-7 measurement before continuing)
```

## Phase 5 — Run the commissioning gates

```sh
# from the management host, against the target over serial or ssh:
python3 scripts/commission-check.py --ssh root@<device>          # or: --serial /dev/ttyUSB0
```

`commission-check.py` runs the full gate battery (boot / floor / egress / attest / tiers / containment) and
prints a PASS/FAIL report + a GO/NO-GO verdict. It marks each gate `[HW]` (only proves out on real hardware:
nested-KVM / real-TPM / real-NIC) or `[qemu-ok]` (already green in the qemu suite). The on-target assertions
mirror the existing `verify-*` scripts (floor/egress/attest/hostile-agent), so a green report on hardware is
the bare-metal analogue of a green `make verify-*` run.

## Phase 6 — Provision

```sh
# 6a. Tailnet join (deploy/tailscale-join.md) — the management plane; the router rebinds to the tailnet address.
# 6b. EK-rooted AK pin (one-time, off-box; ADR-0020) — upgrades attestation from the qemu structural fallback
#     to genuine-silicon: attest ek -> make-credential -> activate -> enroll-verify writes /data/bulkhead/attest-ak.pin.
# 6c. Pin the off-box monitor's TOFU anchors (the AK pin + the 3 chain HEADs) — cross-check the printed pin
#     out-of-band, then run the monitor once and confirm it is GREEN (deploy/chain-monitor.md):
bulkhead-chain-monitor -config /etc/bulkhead/chain-monitor.json -once   # exit 0; NOTICE TOFU AK pin captured
# 6d. Operator approval path over the tailnet (ADR-0007/0009 approve.sock) — note the remote transport is a
#     documented seam (PRODUCTION-READINESS); verify the local path with `make verify-agent-orch` first.
# 6e. Anthropic credential delivery (deploy/anthropic-credential.md), sealed in tpm2 mode.
```

## Phase 7 — Acceptance criteria

A device is **commissioned** only when ALL hold on the real hardware:

- [ ] Phase 4 sealed-boot: the seed + CA decrypt to ciphertext-only on `/data`, re-unseal across a cold reboot,
      and a PCR-7 perturbation fail-closes a consumer.
- [ ] `commission-check.py` → **GO** (every gate PASS, including the `[HW]` ones).
- [ ] Attestation EK-rooted: `attest gate` exit 0 and a fresh-nonce quote verifies against `/data/bulkhead/
      attest-ak.pin` (not the structural fallback).
- [ ] The off-box monitor is pinned and GREEN against this device, its AK pin cross-checked out-of-band.
- [ ] RAUC: `rauc status` shows the active slot `booted=good`; a CA-signed bundle installs + the gate marks it good.

---

## What only proves out on hardware

These gates **cannot** pass in the qemu suite and are the reason commissioning exists:
TPM2-sealed boot + the PCR-7 fail-closed (real TPM) · EK-rooted attestation (genuine EK cert) · the Firecracker
microVM + jailer (`make verify-firecracker-*`, real `/dev/kvm`) · runsc `--platform=kvm` · the nftables
default-deny floor against a **real NIC + real routes** (slirp masks direct-IP/DNS-leak behavior).

## Deferred seams the operator must own

- **Secure Boot signing** (PK/KEK/db + sbsign) — not in-tree (Phase 3).
- **PCR-7 seed-escrow / restore** — no escrow script or tested restore path (ADR-0039 seam); a legitimate
  firmware/SB/TPM-RMA change perturbs PCR 7 and bricks the box until the seed is restored or re-sealed with
  `BULKHEAD_SEAL_FORCE_NEW=1` (which **discards** prior audit history). See `docs/INCIDENT-RESPONSE.md` Playbook B.
- **No `/data` backup/restore** — the chains, sealed seed, and MITM CA on `/data` have no shipped backup.
- **Monitor re-pin** — re-anchoring a legitimately-changed AK/HEAD is a manual edit of `state_dir/device-*.json`.
- **The bare-metal device-path divergence** (`system.conf` `/dev/sda*`) — fix for your storage before flash.
