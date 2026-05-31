# ADR 0003 — Yocto production migration

- **Status:** Accepted (migration in progress)
- **Date:** 2026-05-31
- Follows [ADR 0001](0001-foundational-architecture.md): "Buildroot prototype →
  Yocto production." v1 is the proven Buildroot prototype; this ADR plans the
  reproducible, atomically-updatable production distribution.

## Why migrate

Buildroot gave us a fast, working prototype (v1: M0–M5, all verified). It does
not give us **atomic A/B updates, a signed/immutable rootfs, SBOM + CVE tracking,
or long-term reproducible release engineering** — the things a deployable
security appliance needs. Yocto does. The architecture and every design decision
(ADR 0001/0002) carry over unchanged; only the build system and update mechanism
change.

## Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | **Yocto LTS: scarthgap (5.0)** | Mature, widely deployed, supported to 2028, first-class `meta-rauc`. (wrynose 6.0 is newer/longer-support but less shaken-out; revisit at the next LTS.) |
| 2 | **Kernel: scarthgap's linux-yocto 6.6 LTS** with the bulkhead security fragment ported verbatim | scarthgap ships 6.6 LTS (not 6.12); the v1 floor (BPF-LSM, Landlock, BTF, CGROUP_BPF, FUNCTION_TRACER…) is fully present in 6.6, so we align with the LTS's tested kernel rather than carry a custom 6.12 recipe. A `linux-yocto` bbappend carries the fragment + `lsm=` cmdline. |
| 3 | **Updates: RAUC A/B, `verity` bundle format** | Immutable, authenticated, rollback-capable. x86_64 uses the **GRUB** backend (grubenv on a non-redundant partition) — systemd-boot is not a RAUC backend. |
| 4 | **Read-only rootfs + a persistent data partition** | `IMAGE_FEATURES += "read-only-rootfs"`; `/var/lib/bulkhead` (audit log, tailscaled/credential state) and the model live on a persistent partition, not a RAUC slot. |
| 5 | **Signing keys off-repo (PKCS#11/KMS)** | `RAUC_KEY_FILE`/`RAUC_CERT_FILE` point at out-of-tree paths or a PKCS#11 URI; only the CA trust anchor ships on the device. Never committed (same posture as every other secret). |
| 6 | **SBOM + CVE via `create-spdx` (+ `sbom-cve-check`)** | Per-image SPDX 3.0 in the deploy dir; cheap, on-brand for a security appliance. |
| 7 | **Reproducibility: pin every layer SRCREV (no AUTOREV), lock DISTRO/MACHINE, shared sstate + hashserv** | Deterministic, attestable release builds. |
| 8 | **Measured boot + TPM attestation** | Post-migration: UEFI Secure Boot + measured boot; the appliance attests its state, complementing the signed provenance log. |

## Layer + build layout

```
yocto/
├── README.md                 build instructions, host deps, pinned refs
├── scripts/fetch-yocto.sh    clone poky + meta-openembedded + meta-rauc @ scarthgap (pinned)
└── (poky/, meta-*/  — fetched, gitignored)
meta-bulkhead/                the bulkhead layer (committed)
├── conf/layer.conf
├── conf/distro/bulkhead.conf            systemd, rauc, read-only-rootfs, SPDX, security flags
├── recipes-kernel/linux/linux-yocto_%.bbappend   6.12 + the security fragment + lsm= cmdline
├── recipes-core/images/bulkhead-image.bb         the appliance image (RAUC slot)
├── recipes-bulkhead/bulkhead-router_0.1.0.bb     reuse src/router (go.bbclass)
├── recipes-bulkhead/bulkhead-collector_0.1.0.bb  reuse src/collector (vendored, go.bbclass)
├── recipes-bulkhead/llama-cpp_*.bb               cmake; CUDA variant for the GPU build
├── recipes-bulkhead/tailscale_*.bb               or meta-oe's
├── recipes-bulkhead/bulkhead-units/              the systemd units + nftables.conf (from the overlay)
└── recipes-support/rauc/                         system.conf (A/B slots, grub), bundle recipe
```

## Buildroot → Yocto mapping

| Buildroot (v1) | Yocto (production) |
|---|---|
| `bulkhead_defconfig` | `conf/distro/bulkhead.conf` + `bulkhead-image.bb` |
| `linux-bulkhead.fragment` | `linux-yocto_%.bbappend` (`SRC_URI += fragment`, `KERNEL_FEATURES`) |
| `BR2_INIT_SYSTEMD` | `DISTRO_FEATURES += "systemd"`, `VIRTUAL-RUNTIME_init_manager = "systemd"` |
| `package/llama-cpp` (cmake-package) | `llama-cpp_*.bb` (`inherit cmake`) |
| `package/bulkhead-router` (golang-package, local) | `bulkhead-router_*.bb` (`inherit go-mod`, `SRC_URI = file://…`) |
| `package/bulkhead-collector` (vendored) | `bulkhead-collector_*.bb` (vendored modules + committed bpf2go object) |
| `package/tailscale-bin` | `tailscale_*.bb` (or meta-oe) |
| rootfs-overlay units + `nftables.conf` | `bulkhead-units` recipe installing to `${systemd_system_unitdir}` etc. |
| model data disk | a persistent data partition (wic image) + first-boot provisioning |
| reflash | RAUC A/B verity bundles |

## Build expectations (be honest)

A full Yocto image build is **multi-hour** (fetch + from-scratch compile of the
toolchain, kernel, systemd, and every package) and requires host packages
(`chrpath`, `diffstat`, `lz4`, `file`, etc.). The migration proceeds in
increments — layer + distro, then kernel parity, then each component recipe,
then the image, then RAUC bundles — each verified before the next. This is a
phase, not a single build.

## Status

Scaffolding the `meta-bulkhead` layer + build tooling. Next: kernel-config
parity (6.12 + fragment), then port the router/collector/llama recipes, build
the image, and add RAUC A/B.
