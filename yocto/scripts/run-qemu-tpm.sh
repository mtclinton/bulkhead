#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Boot the bulkhead Yocto wic image under qemu with a software TPM 2.0 (swtpm) attached,
# for measured-boot + sealed-credential verification (ADR-0008). runqemu has no TPM logic,
# so we launch a host swtpm socket and pass the qemu TPM device through `qemuparams=`.
#
# The TPM state dir PERSISTS across boots when BULKHEAD_TPMSTATE is set to a fixed path —
# required to prove a sealed credential unseals identically across a reboot. Leave it
# unset for a fresh (tamper-sim) TPM each run.
#
# Usage:
#   yocto/scripts/run-qemu-tpm.sh                 # ephemeral TPM state (fresh PCRs)
#   BULKHEAD_TPMSTATE=/tmp/bh-tpm run-qemu-tpm.sh # persistent TPM state across reboots
#   BULKHEAD_EXTRA_QEMUPARAMS="-drive file=bundle.img,if=virtio,format=raw,readonly=on" \
#       run-qemu-tpm.sh                           # attach an extra disk (e.g. a RAUC bundle)
#   (any trailing args are appended to runqemu, e.g. `snapshot`)
set -euo pipefail

command -v swtpm >/dev/null 2>&1 || { echo "ERROR: swtpm not installed (apt-get install swtpm swtpm-tools)"; exit 3; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"          # the yocto/ dir
BUILD="$ROOT/build"

TPMDIR="${BULKHEAD_TPMSTATE:-$(mktemp -d /tmp/bh-swtpm.XXXXXX)}"
mkdir -p "$TPMDIR"
SOCK="$TPMDIR/swtpm-sock"

# Initialize TPM state once (idempotent: skip if a state file already exists).
if [ ! -e "$TPMDIR/tpm2-00.permall" ]; then
	swtpm_setup --tpm2 --tpmstate "$TPMDIR" --create-ek-cert --create-platform-cert --lock-nvram >/dev/null 2>&1 || \
		swtpm_setup --tpm2 --tpmstate "$TPMDIR" --lock-nvram >/dev/null 2>&1 || true
fi

# Start the swtpm control socket in the background; clean it up on exit. The startup
# flags govern how/whether swtpm runs TPM2_Startup (overridable: the firmware-vs-kernel
# startup handshake is finicky under OVMF — see ADR-0008 / systemd #21747).
SWTPM_FLAGS="${BULKHEAD_SWTPM_FLAGS:-not-need-init,startup-clear}"
swtpm socket --tpm2 --tpmstate dir="$TPMDIR" --ctrl type=unixio,path="$SOCK" --flags "$SWTPM_FLAGS" &
SWTPM_PID=$!
trap 'kill "$SWTPM_PID" 2>/dev/null || true' EXIT
# Wait for the control socket to appear.
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done

cd "$BUILD"
# oe-init-build-env is not written for `set -e`/`set -u` (it references unset vars and
# returns non-zero); relax both around the source only, then restore.
set +eu
# shellcheck disable=SC1091
source ../poky/oe-init-build-env . >/dev/null 2>&1 || true
set -eu

echo "[run-qemu-tpm] TPM state: $TPMDIR  (persistent: ${BULKHEAD_TPMSTATE:+yes}${BULKHEAD_TPMSTATE:-no})"
# -m 512: the default 256 MiB is too tight for the ADR-0023 self-check (TPM quote + reading the
# collector binary) on top of the running topology — it intermittently OOM-killed the collector. qemu
# honors the last -m, so this overrides runqemu's QB_MEM default.
# BULKHEAD_EXTRA_QEMUPARAMS (optional): folded into the SINGLE qemuparams= string (runqemu keeps only the
# last qemuparams=, so it must be merged here, not passed separately). Used to attach an extra virtio disk —
# e.g. a RAUC update bundle for the A/B failover test (scripts/qemu-rauc-check.py).
QEMUPARAMS="-m 512 -chardev socket,id=chrtpm,path=$SOCK -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 ${BULKHEAD_EXTRA_QEMUPARAMS:-}"
exec runqemu qemux86-64 wic ovmf nographic kvm slirp \
	qemuparams="$QEMUPARAMS" \
	"$@"
