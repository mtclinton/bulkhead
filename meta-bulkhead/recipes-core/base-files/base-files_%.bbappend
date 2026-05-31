# SPDX-License-Identifier: AGPL-3.0-only
# bulkhead provides its own fstab for the RAUC A/B layout (overrides the
# meta-rauc-qemux86 demo fstab; meta-bulkhead has higher layer priority).
FILESEXTRAPATHS:prepend := "${THISDIR}/${BPN}:"

# Mountpoint dirs for the data + grubenv partitions.
dirs755 += "/data"
dirs755 += "/grubenv"
