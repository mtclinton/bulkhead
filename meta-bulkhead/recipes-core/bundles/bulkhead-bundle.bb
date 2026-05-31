# SPDX-License-Identifier: AGPL-3.0-only
SUMMARY = "bulkhead RAUC update bundle (A/B rootfs + bootloader slot)"
LICENSE = "AGPL-3.0-only"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/AGPL-3.0-only;md5=73f1eb20517c55bf9493b7dd6e480788"

inherit bundle

# Must match the device system.conf compatible byte-for-byte (meta-bulkhead ships its
# own system.conf with this string via recipes-core/rauc/files/qemux86-64/system.conf).
RAUC_BUNDLE_COMPATIBLE = "bulkhead appliance"

# verity: dm-verity-protected bundle (authenticated, integrity-checked at install).
RAUC_BUNDLE_FORMAT = "verity"

RAUC_BUNDLE_SLOTS = "efi rootfs"

# The rootfs slot ships the full bulkhead appliance image as a tarball, unpacked
# into the inactive A/B slot on install.
RAUC_IMAGE_FSTYPE = "tar.bz2"
RAUC_SLOT_rootfs = "bulkhead-image"

# The EFI/GRUB boot partition image (atomic bootloader updates).
RAUC_SLOT_efi = "boot-image"
RAUC_SLOT_efi[file] = "efi-boot.vfat"
RAUC_SLOT_efi[type] = "boot"
