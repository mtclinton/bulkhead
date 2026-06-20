#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# ADR-0031 tier-SELECTION policy proof (PRODUCTION-READINESS [81]). Exercises the resolver
# (bulkhead-agent-tier-launch) host-side — pure logic, no systemd — over the SHIPPED policy and crafted
# policies, asserting the FAIL-CLOSED invariants: an unknown/unvetted class never lands in the weakest
# (confined) tier, `default` is sanitized up to at least runsc, firecracker degrades to runsc without KVM,
# and an EXPLICIT class->confined opt-in is honored. Also dry-run-dispatches to confirm the unit mapping.
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/external/board/bulkhead/rootfs-overlay/usr/bin/bulkhead-agent-tier-launch"
SHIPPED="$REPO/external/board/bulkhead/rootfs-overlay/etc/bulkhead/tier-policy.conf"
PASS=0; FAIL=0
ok()  { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

[ -f "$SCRIPT" ]  || { echo "TIER POLICY INCOMPLETE (resolver not found)"; exit 1; }
[ -f "$SHIPPED" ] || { echo "TIER POLICY INCOMPLETE (shipped policy not found)"; exit 1; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# er <desc> <policy> <kvm 1|0> <class> <want-tier>
er() {
	got="$(BULKHEAD_TIER_POLICY="$2" BULKHEAD_TIER_KVM="$3" sh "$SCRIPT" --resolve "$4" 2>/dev/null || true)"
	if [ "$got" = "$5" ]; then ok "$1 [$4 -> $got]"; else bad "$1 [$4 -> '$got', want '$5']"; fi
}

echo "=== shipped policy ($SHIPPED), KVM present ==="
er "hostile -> firecracker"                 "$SHIPPED" 1 hostile     firecracker
er "untrusted -> runsc"                      "$SHIPPED" 1 untrusted   runsc
er "internal -> confined (explicit opt-in)"  "$SHIPPED" 1 internal    confined
er "unknown class -> runsc (default)"        "$SHIPPED" 1 zz-unknown  runsc
er "the 'default' class itself -> runsc"     "$SHIPPED" 1 default     runsc

echo "=== shipped policy, NO KVM: firecracker degrades, never below runsc ==="
er "hostile degrades firecracker -> runsc"   "$SHIPPED" 0 hostile     runsc
er "internal still confined (explicit)"      "$SHIPPED" 0 internal    confined

echo "=== FAIL-CLOSED: an unknown class can never be sent to confined ==="
printf 'default = confined\ninternal = confined\n' > "$TMP/defconf"
er "default=confined sanitized: unknown -> runsc"        "$TMP/defconf" 1 zz-unknown runsc
er "default=confined: explicit internal still confined"  "$TMP/defconf" 1 internal   confined
printf 'hostile = firecracker\n' > "$TMP/nodef"
er "no default line: unknown -> runsc"                   "$TMP/nodef"   1 zz-unknown runsc
er "missing policy file: unknown -> runsc"               "$TMP/nope"    1 zz-unknown runsc
er "missing policy file: hostile -> runsc"               "$TMP/nope"    1 hostile    runsc

echo "=== malformed / robustness ==="
printf 'default = runsc\nhostile = banana\n' > "$TMP/badval"
er "invalid tier value falls through to default"         "$TMP/badval"  1 hostile    runsc
printf 'default = firecracker\n' > "$TMP/deffc"
er "default may be STRONGER than runsc (KVM)"            "$TMP/deffc"   1 zz-unknown firecracker
er "default=firecracker degrades without KVM"           "$TMP/deffc"   0 zz-unknown runsc
printf '  hostile   =   firecracker   # trailing\n# whole-line comment\nhostile = runsc\n' > "$TMP/msg"
er "whitespace + comments + last-wins"                   "$TMP/msg"     1 hostile    runsc

echo "=== dispatch (dry-run) maps to the correct unit ==="
d() { BULKHEAD_TIER_POLICY="$SHIPPED" BULKHEAD_TIER_KVM="$1" BULKHEAD_TIER_DRYRUN=1 sh "$SCRIPT" "$2" "$3" 2>/dev/null || true; }
[ "$(d 1 worker hostile)" = "WOULD-START bulkhead-agent-firecracker@worker.service" ] \
	&& ok "dispatch hostile -> firecracker unit" || bad "dispatch hostile -> '$(d 1 worker hostile)'"
[ "$(d 1 worker '')" = "WOULD-START bulkhead-agent-runsc@worker.service" ] \
	&& ok "dispatch no class -> default(runsc) unit" || bad "dispatch default -> '$(d 1 worker '')'"
[ "$(d 0 worker hostile)" = "WOULD-START bulkhead-agent-runsc@worker.service" ] \
	&& ok "dispatch hostile without KVM -> runsc unit" || bad "dispatch hostile/no-kvm -> '$(d 0 worker hostile)'"
if BULKHEAD_TIER_DRYRUN=1 sh "$SCRIPT" 'bad id!' default >/dev/null 2>&1; then bad "invalid instance id accepted"; else ok "invalid instance id rejected (exit != 0)"; fi

echo
echo "=== tier-selection policy: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && { echo "TIER POLICY GO"; exit 0; } || { echo "TIER POLICY INCOMPLETE"; exit 1; }
