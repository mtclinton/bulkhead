#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# RAUC install-check hook (ADR-0039 seam): refuse a bundle OLDER than the running system version, so a
# still-validly-signed PAST release cannot be replayed to reintroduce a patched vulnerability (no
# downgrade below the INSTALLED version). This is the DYNAMIC complement to system.conf's STATIC
# min-bundle-version floor: the floor (device-side) blocks everything below a fixed point and catches even
# pre-hook bundles; this hook (bundle-side) additionally blocks a downgrade below whatever is running now,
# among hook-carrying releases. RAUC treats a hook exit code >= 10 as "reject this bundle".
#
# Running version: /etc/os-release VERSION_ID (Yocto sets it from DISTRO_VERSION; the hook runs in the
# RUNNING system's filesystem context, so this is the installed version, not the bundle's). The
# BULKHEAD_RUNNING_VERSION override exists ONLY so the logic is host-testable without a second bundle.
[ "$1" = "install-check" ] || exit 0

running="${BULKHEAD_RUNNING_VERSION:-}"
if [ -z "$running" ] && [ -r /etc/os-release ]; then
	running=$(. /etc/os-release 2>/dev/null && printf '%s' "$VERSION_ID")
fi
incoming="$RAUC_MF_VERSION"

# If either version is missing/empty, defer to the static min-bundle-version floor — do NOT reject here.
[ -n "$running" ] && [ -n "$incoming" ] || exit 0

# Reject iff incoming < running. busybox has no `sort -V`, so compare the dotted fields numerically in awk:
# exit 0 means incoming < running (a downgrade -> reject); exit 1 means incoming >= running (allow).
if awk -v a="$incoming" -v b="$running" 'BEGIN {
		split(a, A, "."); split(b, B, ".");
		for (i = 1; i <= 3; i++) { x = A[i] + 0; y = B[i] + 0; if (x < y) exit 0; if (x > y) exit 1 }
		exit 1
	}'; then
	echo "bulkhead: REFUSING downgrade — bundle version '$incoming' is older than the running '$running'" >&2
	exit 10
fi
exit 0
