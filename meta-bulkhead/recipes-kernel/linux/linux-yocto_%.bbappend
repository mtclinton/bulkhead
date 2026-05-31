# SPDX-License-Identifier: AGPL-3.0-only
# Carry the verified v1 kernel security floor into the Yocto kernel.
FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

SRC_URI += "file://bulkhead-security.cfg"

# The 'bpf' and 'landlock' LSMs must be in the active list; set it on the kernel
# command line via the bootloader (wic/grub) as well:
#   lsm=landlock,lockdown,yama,bpf
# (mirrors scripts/run-qemu.sh and the v1 cmdline)
