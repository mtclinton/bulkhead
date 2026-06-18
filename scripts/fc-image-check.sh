#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# ADR-0042 Firecracker hostile tier — IN-IMAGE landing gate (slices 5-6). The mechanism is live-proven
# host-side (fc-{legs,agent,proxy,jail}-check); this is the complementary check that the DEPLOYABLE tier
# actually shipped into the production image rootfs and is well-formed — so the landing cannot silently rot
# (a recipe rename, a dropped IMAGE_INSTALL line, a units-glob miss, a corrupt vmlinux extraction). It needs
# NO /dev/kvm: it only inspects the built rootfs (or, if rm_work cleaned it, the deployed tar.bz2).
#   - the three binaries (firecracker, jailer, bulkhead-fc-vsockmux) are present + ELF;
#   - the guest vmlinux is an ELF executable (NOT the gzip'd bzImage firecracker rejects);
#   - mkfs.ext4 is present (the launcher's runtime rootfs build);
#   - the launcher is present + parses (sh -n) + carries the proven-flow invariants (no network-interfaces
#     stanza, a vsock leg, --no-api) and NOT a hardcoded /usr/bin/busybox (the no-ldd-in-image lesson);
#   - both @.service templates are present + well-formed, the mux unit keeps its hardening floor
#     (AF_UNIX-only, io_uring denied by name, DynamicUser, 0700 RuntimeDirectory), and the agent unit
#     Requires the mux + proxy + the fail-closed selftest gate.
set -eu

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0; FAIL=0
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

# Source the image contents: prefer the rootfs dir (fast, no extraction); fall back to the deployed tar.bz2.
R="$(ls -d "$REPO"/yocto/build/tmp/work/*/bulkhead-image/*/rootfs 2>/dev/null | head -1 || true)"
TB="$(ls "$REPO"/yocto/build/tmp/deploy/images/*/bulkhead-image-*.rootfs.tar.bz2 \
        "$REPO"/yocto/build/tmp/deploy/images/*/bulkhead-image-*.tar.bz2 2>/dev/null | head -1 || true)"
if [ -n "$R" ]; then
	MODE=dir; echo "image source: rootfs dir $R"
	have()  { [ -e "$R/$1" ]; }
	slurp() { cat "$R/$1"; }
elif [ -n "$TB" ]; then
	MODE=tar; echo "image source: deployed tarball $TB"
	have()  { tar tjf "$TB" "./$1" >/dev/null 2>&1 || tar tjf "$TB" "$1" >/dev/null 2>&1; }
	slurp() { tar xjOf "$TB" "./$1" 2>/dev/null || tar xjOf "$TB" "$1" 2>/dev/null; }
else
	echo "FC IMAGE INCONCLUSIVE (no built bulkhead-image rootfs or tarball — run: bitbake bulkhead-image)"; exit 2
fi

# (1) the three tier binaries are present + ELF
for b in usr/bin/firecracker usr/bin/jailer usr/bin/bulkhead-fc-vsockmux; do
	if have "$b" && slurp "$b" | head -c4 | od -An -tx1 2>/dev/null | grep -q '7f 45 4c 46'; then
		ok "$b present + ELF"
	else
		bad "$b missing or not ELF"
	fi
done

# (2) the guest kernel is an ELF vmlinux, not the gzip'd bzImage
if have usr/share/bulkhead/fc/vmlinux && slurp usr/share/bulkhead/fc/vmlinux | head -c4 | od -An -tx1 2>/dev/null | grep -q '7f 45 4c 46'; then
	ok "guest vmlinux present + ELF (not the gzip'd bzImage)"
else
	bad "guest vmlinux missing or not an ELF (firecracker would reject it)"
fi

# (3) mkfs.ext4 for the launcher's runtime rootfs build
if have sbin/mkfs.ext4 || have usr/sbin/mkfs.ext4; then ok "mkfs.ext4 present (e2fsprogs-mke2fs)"; else bad "mkfs.ext4 missing"; fi

# (4) the launcher: present, parses, carries the proven-flow invariants
L=usr/bin/bulkhead-agent-firecracker-launch
if have "$L"; then
	LB="$(slurp "$L")"
	printf '%s' "$LB" | sh -n 2>/dev/null && ok "launcher parses (sh -n)" || bad "launcher does NOT parse"
	# match the JSON config KEY (always quoted), not the explanatory comment that names the absent stanza
	printf '%s' "$LB" | grep -q '"network-interfaces"' && bad "launcher has a network-interfaces stanza (would give the guest a NIC!)" || ok "launcher omits the network-interfaces stanza (no-NIC structural)"
	printf '%s' "$LB" | grep -q '"vsock"' && ok "launcher provisions a vsock leg" || bad "launcher has no vsock leg"
	printf '%s' "$LB" | grep -q -- '--no-api' && ok "launcher boots firecracker --no-api (config-driven)" || bad "launcher missing --no-api"
	# the no-ldd-in-image lesson: the launcher must NOT depend on a hardcoded busybox path / ldd
	printf '%s' "$LB" | grep -q 'command -v busybox' && ok "launcher resolves busybox via command -v (no hardcoded path)" || bad "launcher does not resolve busybox portably"
else
	bad "launcher $L missing"
fi

# (5) the two @.service templates, in the system unit dir, well-formed
MUX=usr/lib/systemd/system/bulkhead-fc-vsockmux@.service
AGT=usr/lib/systemd/system/bulkhead-agent-firecracker@.service
for u in "$MUX" "$AGT"; do
	if have "$u"; then
		UB="$(slurp "$u")"
		printf '%s' "$UB" | grep -q '^\[Unit\]' && printf '%s' "$UB" | grep -q '^\[Service\]' && printf '%s' "$UB" | grep -q '^ExecStart=' \
			&& ok "$(basename "$u") present + well-formed" || bad "$(basename "$u") malformed"
	else
		bad "$(basename "$u") missing from the system unit dir"
	fi
done

# (6) the mux unit keeps its hardening floor
if have "$MUX"; then
	UB="$(slurp "$MUX")"
	printf '%s' "$UB" | grep -q 'RestrictAddressFamilies=AF_UNIX'      && ok "mux: AF_UNIX-only"                 || bad "mux: AF_UNIX-only floor missing"
	printf '%s' "$UB" | grep -q 'io_uring_setup'                       && ok "mux: io_uring denied by name"      || bad "mux: io_uring deny missing"
	printf '%s' "$UB" | grep -q 'DynamicUser=yes'                      && ok "mux: DynamicUser"                  || bad "mux: DynamicUser missing"
	printf '%s' "$UB" | grep -q 'RuntimeDirectoryMode=0700'            && ok "mux: 0700 per-instance dir"        || bad "mux: 0700 RuntimeDirectory missing"
fi

# (7) the agent unit gates on the mux + proxy + the fail-closed selftest
if have "$AGT"; then
	UB="$(slurp "$AGT")"
	printf '%s' "$UB" | grep -Eq 'Requires=.*bulkhead-fc-vsockmux@%i' && ok "agent unit Requires the per-instance mux" || bad "agent unit does not Require the mux"
	printf '%s' "$UB" | grep -Eq 'Requires=.*bulkhead-egress-proxy'   && ok "agent unit Requires the egress proxy"     || bad "agent unit does not Require the proxy"
	printf '%s' "$UB" | grep -Eq 'Requires=.*bulkhead-selftest'       && ok "agent unit Requires the selftest gate"    || bad "agent unit does not Require the selftest gate"
fi

echo
echo "=== Firecracker in-image landing ($MODE): $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && { echo "FC IMAGE GO"; exit 0; } || { echo "FC IMAGE INCOMPLETE"; exit 1; }
