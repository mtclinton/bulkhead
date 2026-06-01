# bulkhead — Yocto production build

The production distribution (atomic A/B RAUC updates, immutable verity rootfs,
SBOM/CVE, reproducible releases). Design + rationale: [ADR-0003](../docs/decisions/0003-yocto-production-migration.md).
The committed layer is [`meta-bulkhead/`](../meta-bulkhead); poky and the other
layers are fetched (not vendored).

> **This is a multi-hour build and changes the host.** Yocto compiles the whole
> distribution from source. Do not expect a bootable image in minutes.

## Host prerequisites

Yocto needs build packages not required by the Buildroot prototype, e.g. on
Debian/Ubuntu:

```sh
sudo apt-get install -y gawk wget git diffstat unzip texinfo gcc build-essential \
  chrpath socat cpio python3 python3-pip python3-pexpect xz-utils debianutils \
  iputils-ping python3-git python3-jinja2 python3-subunit zstd liblz4-tool file \
  locales libacl1
```

## Build flow

```sh
yocto/scripts/fetch-yocto.sh                 # clone poky + meta-openembedded + meta-rauc(+community) + meta-security @ scarthgap
source yocto/poky/oe-init-build-env yocto/build
bitbake-layers add-layer ../meta-openembedded/meta-oe ../meta-openembedded/meta-python \
  ../meta-openembedded/meta-networking ../meta-rauc ../meta-rauc-community/meta-rauc-qemux86 \
  ../meta-security ../meta-security/meta-tpm ../../meta-bulkhead   # meta-security/meta-tpm: measured boot + sealed audit key (ADR-0008)
# select the bulkhead distro + a machine (qemux86-64 to mirror the prototype):
echo 'DISTRO = "bulkhead"'     >> conf/local.conf
echo 'MACHINE = "qemux86-64"'  >> conf/local.conf
bitbake bulkhead-image                       # multi-hour first build
runqemu qemux86-64 bulkhead-image nographic  # boot it
```

Per-image SPDX SBOM lands in `tmp/deploy/images/<machine>/`.

## Migration status

`meta-bulkhead` currently provides the layer, the `bulkhead` distro (systemd +
rauc + read-only-rootfs + SPDX), the kernel security parity (`bulkhead-security.cfg`
+ the `lsm=` cmdline), and the image skeleton. **Remaining increments** (each
verified before the next):

1. **Component recipes** — `bulkhead-router` / `bulkhead-collector` (`inherit
   go-mod`, reusing `src/`), `llama-cpp` (`inherit cmake`; CUDA variant for GPU),
   `tailscale`, and a `bulkhead-units` recipe installing the systemd units +
   `nftables.conf` from the v1 rootfs-overlay.
2. **Image + wic** — partition layout: A/B rootfs slots + EFI (grub) + a
   persistent data partition for the audit log / model / state.
3. **RAUC** — `system.conf` (A/B, grub backend), verity bundle recipe, signing
   keys via PKCS#11/KMS (off-repo); CA trust anchor on the device.
4. **Hardening** — UEFI Secure Boot + measured boot + TPM attestation; the
   dnsmasq dynamic egress allowlist (Anthropic + Tailscale DERP).
5. **GPU** — `MACHINE` + `llama-cpp` CUDA build for the bare-metal RTX target
   (Qwen3-14B).
