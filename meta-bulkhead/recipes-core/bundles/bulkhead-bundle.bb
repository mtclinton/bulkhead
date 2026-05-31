# SPDX-License-Identifier: AGPL-3.0-only
SUMMARY = "bulkhead RAUC update bundle (A/B rootfs + bootloader slot)"
LICENSE = "AGPL-3.0-only"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/AGPL-3.0-only;md5=73f1eb20517c55bf9493b7dd6e480788"

inherit bundle

# Must match the compatible string in the device's RAUC system.conf. (Currently the
# meta-rauc-qemux86 reference system.conf; a bulkhead-specific compatible + keyring
# is a follow-up once the A/B mechanism is proven.)
RAUC_BUNDLE_COMPATIBLE = "qemux86-64 demo platform"

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
