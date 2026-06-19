#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# HOSTILE-agent containment proof for the FIRECRACKER tier on REAL /dev/kvm (PRODUCTION-READINESS [6], the
# substrate half). Boots a microVM (the FC-tuned guest kernel, NO network-interfaces stanza => no NIC) running
# the agent's `probe-escape` in substrate mode, and asserts the floor held: every HOST-CROSSING vector
# (io_uring mediation, direct egress, the host control socket, a host-only secret planted OUTSIDE the VM) is
# CONTAINED. In-sandbox-privilege ops (setuid/capset/...) may report SANDBOX-PRIV — the agent is in-VM root by
# design and the VM boundary contains it (ADR-0031's accepted residual is a VMM/KVM 0-day, not in-guest uid).
# Host-side on real hardware virtualization; exits 2 without /dev/kvm.
set -eu

FC="${FIRECRACKER:-/home/work/bin/firecracker}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMG="$REPO/yocto/build/tmp/deploy/images/qemux86-64"
W="${FC_ESCAPE_WORK:-/tmp/fc-escape}"
PASS=0; FAIL=0
ok()  { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

[ -e /dev/kvm ] && ok "/dev/kvm present (real hardware virtualization)" || { echo "FC ESCAPE INCONCLUSIVE (no /dev/kvm)"; exit 2; }
[ -x "$FC" ] || { bad "firecracker not executable at $FC"; echo "FC ESCAPE INCOMPLETE"; exit 1; }
BZ="$(readlink -f "$IMG/bzImage" 2>/dev/null || true)"; [ -f "$BZ" ] || { bad "no deploy bzImage"; echo "FC ESCAPE INCOMPLETE"; exit 1; }
EV="$(find "$REPO/yocto/build/tmp/work" -path '*scripts/extract-vmlinux' 2>/dev/null | head -1)"; [ -n "$EV" ] || { bad "no extract-vmlinux"; echo "FC ESCAPE INCOMPLETE"; exit 1; }

rm -rf "$W"; mkdir -p "$W"
sh "$EV" "$BZ" > "$W/vmlinux" 2>/dev/null
head -c4 "$W/vmlinux" | od -An -tx1 | grep -q "7f 45 4c 46" && ok "extracted ELF vmlinux (the io_uring-off guest kernel)" || { bad "no ELF vmlinux"; echo "FC ESCAPE INCOMPLETE"; exit 1; }

( cd "$REPO/src/agent" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$W/bulkhead-agent.guest" . ) || { bad "guest agent build"; echo "FC ESCAPE INCOMPLETE"; exit 1; }
ok "built the static agent (the hostile payload)"

# A host-only secret planted OUTSIDE the VM (the build host's fs). The guest is a SEPARATE kernel + ext4, so it
# cannot see it — reading it must ENOENT (the strongest fs-isolation test). World-readable so only ISOLATION hides it.
SECRET="$W/.host-only-secret"; echo "TOP-SECRET-HOST-ONLY" > "$SECRET"; chmod 644 "$SECRET"

# Guest rootfs: busybox + the agent + an init that runs probe-escape in substrate mode.
RT="$W/rootfs"; mkdir -p "$RT/bin" "$RT/proc" "$RT/dev" "$RT/run"
cp "$(command -v busybox)" "$RT/bin/busybox"
for lib in $(ldd "$(command -v busybox)" 2>/dev/null | grep -oE '/[^ ]+\.so[0-9.]*'); do
	mkdir -p "$RT$(dirname "$lib")"; cp -L "$lib" "$RT$lib"
done
cp "$W/bulkhead-agent.guest" "$RT/bin/bulkhead-agent"
ln -sf busybox "$RT/bin/sh"
cat > "$RT/init" <<EOF
#!/bin/busybox sh
/bin/busybox mount -t proc proc /proc 2>/dev/null
/bin/busybox mount -t devtmpfs dev /dev 2>/dev/null
echo FC-ESCAPE-BEGIN
BULKHEAD_PROBE_TIER=substrate BULKHEAD_PROBE_HOST_SECRET=$SECRET BULKHEAD_PROBE_PUBLIC=1.1.1.1:443 /bin/bulkhead-agent probe-escape
echo FC-ESCAPE-END\$?
/bin/busybox sync
/bin/busybox reboot -f
EOF
chmod +x "$RT/init"
dd if=/dev/zero of="$W/rootfs.ext4" bs=1M count=64 status=none
"$(command -v mkfs.ext4 || echo /sbin/mkfs.ext4)" -F -q -d "$RT" "$W/rootfs.ext4"
ok "built guest rootfs (probe-escape payload, substrate tier)"

# NO network-interfaces stanza (no NIC) and NO vsock (probe-escape needs neither) — the microVM is the boundary.
cat > "$W/vm.json" <<EOF
{
  "boot-source": {"kernel_image_path": "$W/vmlinux", "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda init=/init"},
  "drives": [{"drive_id":"rootfs","path_on_host":"$W/rootfs.ext4","is_root_device":true,"is_read_only":false}],
  "machine-config": {"vcpu_count":1,"mem_size_mib":256}
}
EOF
echo "=== boot microVM on REAL /dev/kvm (no NIC), run probe-escape ==="
OUT="$(timeout 90 "$FC" --no-api --config-file "$W/vm.json" 2>&1 || true)"
echo "----- probe-escape output (in the microVM) -----"
ESC="$(echo "$OUT" | grep -aE 'ESCAPE ')"
echo "$ESC"
echo "------------------------------------------------"

# host-crossing vectors (mediation + host-reach) MUST be contained; in-sandbox-priv may be SANDBOX-PRIV.
for v in IO_URING DIRECT_EGRESS CONTROL_SOCK HOST_SECRET; do
	echo "$ESC" | grep -qE "ESCAPE $v: CONTAINED" && ok "FC tier: $v CONTAINED" || bad "FC tier: $v NOT contained"
done
echo "$ESC" | grep -qE 'ESCAPE RESULT: CONTAINED' && ok "FC tier: RESULT CONTAINED (no host-reach/mediation escape)" || bad "FC tier: RESULT not CONTAINED"
echo "$ESC" | grep -q 'ESCAPE RESULT: BREACH' && bad "FC tier: a host-meaningful vector BREACHED" || ok "FC tier: no BREACH"

echo
echo "=== Firecracker hostile-tier containment (real KVM): $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && { echo "FC ESCAPE CONTAINED"; exit 0; } || { echo "FC ESCAPE INCOMPLETE"; exit 1; }
