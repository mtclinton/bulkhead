# SPDX-License-Identifier: AGPL-3.0-only
# Carry the verified v1 kernel security floor into the Yocto kernel.
FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

SRC_URI += "file://bulkhead-security.cfg"

# CONFIG_DEBUG_INFO_BTF (required for the collector's BPF-LSM CO-RE and for
# /sys/kernel/btf/vmlinux) needs pahole at kernel build time. In linux-yocto.inc,
# KERNEL_DEBUG is used ONLY to gate pahole: when "True" it pulls in pahole-native
# and drops the PAHOLE=false stub. Without it, BTF generation fails the build.
KERNEL_DEBUG = "True"

# The 'bpf' and 'landlock' LSMs must be in the active list; set it on the kernel
# command line via the bootloader (wic/grub) as well:
#   lsm=landlock,lockdown,yama,bpf
# (mirrors scripts/run-qemu.sh and the v1 cmdline)
