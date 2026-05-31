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
"
# tpm2-tss (for sealed credentials) needs meta-security/meta-tpm — added with
# the measured-boot/attestation hardening step.

# RAUC A/B verity slots + a persistent data partition are assembled via wic
# (recipes-support/rauc + a wks layout) — added in the RAUC integration step.
