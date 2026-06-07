# SPDX-License-Identifier: AGPL-3.0-only
SUMMARY = "bulkhead RAUC update bundle (A/B rootfs + bootloader slot)"
LICENSE = "AGPL-3.0-only"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/AGPL-3.0-only;md5=73f1eb20517c55bf9493b7dd6e480788"

inherit bundle

FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

# Downgrade protection part 2 (ADR-0031 seam): an install-check hook that refuses a bundle OLDER than the
# running version (no downgrade below INSTALLED) — the dynamic complement to system.conf's static
# min-bundle-version floor. The hook is signed (part of the bundle), runs in the running system's context,
# and reads /etc/os-release VERSION_ID. Host-tested via `make verify-rauc-hook`.
SRC_URI += "file://bulkhead-install-check.sh"
RAUC_BUNDLE_HOOKS[file] = "bulkhead-install-check.sh"
RAUC_BUNDLE_HOOKS[hooks] = "install-check"

# Must match the device system.conf compatible byte-for-byte (meta-bulkhead ships its
# own system.conf with this string via recipes-core/rauc/files/qemux86-64/system.conf).
RAUC_BUNDLE_COMPATIBLE = "bulkhead appliance"

# Downgrade protection (RAUC update-path audit). A REAL semver version in the signed manifest (the
# meta-rauc default is the frozen PV "1.0", which no min-bundle-version gate can act on). The device
# system.conf sets min-bundle-version so a bundle OLDER than the configured floor is refused at install
# (rauc check_version_limits: install proceeds iff min <= version, equal allowed). Production overrides
# this with a monotonic release version (e.g. ${DISTRO_VERSION}-${RELEASE_SERIAL} tied to the release tag),
# and raises the device floor as old releases age out, so a known-vulnerable signed bundle can't be replayed.
RAUC_BUNDLE_VERSION = "${DISTRO_VERSION}"

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
