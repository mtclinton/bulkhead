# SPDX-License-Identifier: AGPL-3.0-only
SUMMARY = "bulkhead agent appliance image"
LICENSE = "AGPL-3.0-only"

inherit core-image

# Immutable rootfs; mutable state (audit log, tailscaled/credential state, model)
# lives on a separate persistent partition, not a RAUC slot.
IMAGE_FEATURES += "read-only-rootfs"

IMAGE_INSTALL += " \
    bulkhead-router \
    bulkhead-collector \
    bulkhead-units \
    llama-cpp \
    tailscale \
    nftables \
    curl \
    rauc \
    kernel-image \
    kernel-modules \
"
# kernel-image puts /boot/bzImage in each rootfs slot so GRUB can load it per-slot
# (rauc.slot=A|B). rauc carries the system.conf + ca keyring (meta-rauc/meta-rauc-qemux86).
# tpm2-tss (for sealed credentials) needs meta-security/meta-tpm — added with
# the measured-boot/attestation hardening step.

# --- RAUC A/B disk assembly (wic) ---
# wic = the partitioned A/B disk; ext4 = the per-slot rootfs the bundle ships;
# tar.bz2 = what the RAUC rootfs slot packages.
IMAGE_FSTYPES = "tar.bz2 ext4 wic"
WKS_FILE = "bulkhead-grub-efi.wks"
# The EFI/grubenv partitions are raw-copied from boot-image's deploy artifacts.
do_image_wic[depends] += "boot-image:do_deploy"
# 4K-align the rootfs (RAUC adaptive 'block-hash-index' friendliness + clean slots).
IMAGE_ROOTFS_ALIGNMENT = "4"
