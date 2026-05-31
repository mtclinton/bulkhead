#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Build the Tailscale auth-key provisioning volume: a tiny ext4 image holding
# the auth key, attached to the appliance read-only at first join (as /dev/vdc).
# The key is NEVER committed or baked into an image; this reads it from the
# operator's runtime path. Detach the volume after the node has joined.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KEYSRC="${TS_AUTHKEY_FILE:-$HOME/.bulkhead/tsauthkey}"
OUT="$ROOT/output/images/tsauth.ext4"

[ -r "$KEYSRC" ] || { echo "no auth key at $KEYSRC (write it there first)" >&2; exit 1; }

MKFS=""
for c in "$ROOT/output/host/sbin/mkfs.ext4" /usr/sbin/mkfs.ext4 /sbin/mkfs.ext4; do
	[ -x "$c" ] && { MKFS="$c"; break; }
done
[ -n "$MKFS" ] || { echo "mkfs.ext4 not found" >&2; exit 1; }

stage="$(mktemp -d)"
install -m 600 "$KEYSRC" "$stage/authkey"
rm -f "$OUT"
"$MKFS" -q -F -m 0 -L bulkhead-tsauth -d "$stage" "$OUT" 16M
rm -rf "$stage"
echo "tsauth volume: $OUT (key sourced from $KEYSRC; not committed)"
