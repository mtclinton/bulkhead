#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Boot the bulkhead image in qemu (CPU-only). v1 uses direct -kernel boot.
#
# The CPU model is pinned because the appliance binaries (notably llama.cpp)
# are built with GGML_NATIVE=OFF and must not assume the build host's ISA.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMG="$ROOT/output/images"
KERNEL="$IMG/bzImage"
ROOTFS="$IMG/rootfs.ext2"

[ -r "$KERNEL" ] || { echo "missing $KERNEL — run 'make image' first" >&2; exit 1; }
[ -r "$ROOTFS" ] || { echo "missing $ROOTFS — run 'make image' first" >&2; exit 1; }

exec qemu-system-x86_64 \
  -M pc -cpu "${CPU:-max}" -m "${MEM:-4096}" -smp "${SMP:-4}" \
  -kernel "$KERNEL" \
  -drive file="$ROOTFS",if=virtio,format=raw \
  -append "root=/dev/vda rw console=ttyS0 lsm=landlock,lockdown,yama,bpf" \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
  -nographic
