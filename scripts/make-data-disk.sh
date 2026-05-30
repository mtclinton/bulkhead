#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Build the bulkhead model data disk: an ext4 image containing the GGUF model,
# attached to the appliance as a separate read-only virtio volume. This mirrors
# the production design (model on a persistent data volume, NOT the immutable
# rootfs). The model is downloaded at build time and is NEVER committed.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODELS_DIR="$ROOT/output/models"
OUT="$ROOT/output/images/data.ext4"
MODEL_FILE="${MODEL_FILE:-qwen2.5-3b-instruct-q4_k_m.gguf}"
MODEL_URL="${MODEL_URL:-https://huggingface.co/Qwen/Qwen2.5-3B-Instruct-GGUF/resolve/main/${MODEL_FILE}}"

mkdir -p "$MODELS_DIR" "$ROOT/output/images"
if [ ! -f "$MODELS_DIR/$MODEL_FILE" ]; then
	echo "Downloading $MODEL_FILE ..."
	curl -fSL -o "$MODELS_DIR/$MODEL_FILE" "$MODEL_URL"
fi
chmod 0644 "$MODELS_DIR/$MODEL_FILE"

# Size the ext4 to the model plus slack.
bytes=$(stat -c%s "$MODELS_DIR/$MODEL_FILE")
# Slack covers the ext4 journal + metadata; -m 0 drops the 5% root reservation
# (this is a read-only data volume, not a root fs).
sz=$(( bytes / 1048576 + 256 ))
# Resolve mkfs.ext4: prefer Buildroot's host tool (version-matched to the image),
# then the usual sbin locations that are often off a non-root PATH.
MKFS=""
for c in "$ROOT/output/host/sbin/mkfs.ext4" /usr/sbin/mkfs.ext4 /sbin/mkfs.ext4 "$(command -v mkfs.ext4 2>/dev/null || true)"; do
	[ -n "$c" ] && [ -x "$c" ] && { MKFS="$c"; break; }
done
[ -n "$MKFS" ] || { echo "mkfs.ext4 not found (install e2fsprogs or build the image first)" >&2; exit 1; }

echo "Creating ${sz}M ext4 data disk at $OUT using $MKFS"
rm -f "$OUT"
# mkfs.ext4 -d populates the fs from a directory; no root or loop mount needed.
"$MKFS" -q -F -m 0 -L bulkhead-data -d "$MODELS_DIR" "$OUT" "${sz}M"
echo "data disk ready: $OUT"
