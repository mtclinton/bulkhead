#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Host-side check for the RAUC no-downgrade install-check hook (ADR-0031). Drives the hook with crafted
# RAUC_MF_VERSION (incoming) + BULKHEAD_RUNNING_VERSION (running) and asserts the exit code: a downgrade
# rejects (RAUC treats exit >=10 as reject), same/newer/missing allow (exit 0). No qemu, no bundle.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
HOOK="$ROOT/meta-bulkhead/recipes-core/bundles/files/bulkhead-install-check.sh"
[ -r "$HOOK" ] || { echo "FAIL: hook not found at $HOOK"; exit 2; }

fails=0
# expect: REJECT (exit==10) or ALLOW (exit==0)
check() { # <incoming> <running> <expect REJECT|ALLOW> <desc>
	env BULKHEAD_RUNNING_VERSION="$2" RAUC_MF_VERSION="$1" sh "$HOOK" install-check >/dev/null 2>&1
	rc=$?
	want=0; [ "$3" = REJECT ] && want=10
	if [ "$rc" -ne "$want" ]; then
		echo "FAIL: incoming=$1 running=$2 -> exit $rc, want $want ($4)"; fails=$((fails + 1))
	else
		echo "PASS: $4 (incoming=$1 running=$2 -> $rc)"
	fi
}

check 0.0.1 0.1.0 REJECT "downgrade (minor) refused"
check 0.0.9 0.1.0 REJECT "downgrade (within minor) refused"
check 0.9.9 1.0.0 REJECT "downgrade (major) refused"
check 0.1.0 0.1.0 ALLOW  "same version allowed"
check 0.1.1 0.1.0 ALLOW  "patch upgrade allowed"
check 0.2.0 0.1.0 ALLOW  "minor upgrade allowed"
check 1.0.0 0.9.9 ALLOW  "major upgrade allowed"
check ""    0.1.0 ALLOW  "missing incoming defers to the min-bundle-version floor"

# A non-install-check invocation is a no-op (exit 0).
env RAUC_MF_VERSION=0.0.1 sh "$HOOK" slot-post-install >/dev/null 2>&1
[ $? -eq 0 ] || { echo "FAIL: non-install-check arg should exit 0"; fails=$((fails + 1)); }

if [ "$fails" -eq 0 ]; then echo "RAUC HOOK OK"; else echo "RAUC HOOK FAILED ($fails)"; fi
exit "$fails"
