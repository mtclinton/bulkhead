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
    dnsmasq \
    kernel-image \
"
# kernel-image puts /boot/bzImage in each rootfs slot so GRUB can load it per-slot
# (rauc.slot=A|B). No kernel-modules: the security floor + qemu's virtio/ext4/vfat
# drivers are built-in (the bare-qemu boot mounted root with no initramfs), and the
# lockdown LSM would block loading unsigned modules regardless — so they'd be ~500M
# of dead weight. Any genuinely-needed driver becomes a built-in in the fragment.
# rauc carries the system.conf + ca keyring (meta-rauc/meta-rauc-qemux86).
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

# --- Production build hardening ---
# A shippable image MUST NOT carry dev conveniences (empty root password, an
# auto-login serial console, an ssh server, etc.). Production builds set
# BULKHEAD_PRODUCTION = "1" (see yocto/conf/local.conf.production.sample); this then
# fails the build LOUDLY if any insecure image feature leaked in — e.g. poky's default
# EXTRA_IMAGE_FEATURES ?= "debug-tweaks", or the dev A/B-test local.conf. Dev/test
# builds simply leave BULKHEAD_PRODUCTION unset and are unaffected.
python () {
    if d.getVar('BULKHEAD_PRODUCTION') != '1':
        return
    feats = set((d.getVar('IMAGE_FEATURES') or '').split()) | \
            set((d.getVar('EXTRA_IMAGE_FEATURES') or '').split())
    forbidden = {'debug-tweaks', 'empty-root-password', 'allow-empty-password',
                 'allow-root-login', 'post-install-logging', 'serial-autologin-root',
                 'ssh-server-openssh', 'ssh-server-dropbear'}
    leaked = sorted(feats & forbidden)
    if leaked:
        bb.fatal("BULKHEAD_PRODUCTION=1 but insecure/dev image feature(s) present: %s. "
                 "Build with yocto/conf/local.conf.production.sample, not the dev/test "
                 "local.conf." % ", ".join(leaked))
}
