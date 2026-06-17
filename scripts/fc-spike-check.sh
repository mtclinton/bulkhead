#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# ADR-0031 HOSTILE-TIER spike — the runsc-spike analog for the Firecracker tier. Proves Firecracker boots
# a microVM with bulkhead's Yocto guest kernel as a SEPARATE guest kernel (host-surface collapse: a real
# KVM VM, not a namespace), on a KVM-capable build host. Verified HOST-SIDE on purpose: the qemu verify
# harness runs `-cpu IvyBridge` with no nested KVM, so the microVM cannot boot inside the qemu-booted wic;
# the build host (with /dev/kvm + nested) is the spike's vehicle. Later slices add the in-image firecracker
# recipe, a firecracker-tuned guest kernel (io_uring disabled, ADR-0033), the in-VM agent runtime, and the
# mediated egress/router legs (vsock to the host proxy/router).
#
# It: (1) extracts the ELF vmlinux from the deploy bzImage (Firecracker needs ELF, not bzImage); (2) builds
# a minimal busybox rootfs whose /init prints a marker + the guest kernel release; (3) boots the microVM;
# (4) asserts the marker AND that the guest kernel release differs from the host's (a genuine separate
# kernel). Needs a built wic (the bzImage) + firecracker ($FIRECRACKER, default /home/work/bin/firecracker)
# + read access to /dev/kvm.
set -eu

FC="${FIRECRACKER:-/home/work/bin/firecracker}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMG="$REPO/yocto/build/tmp/deploy/images/qemux86-64"
W="${FC_SPIKE_WORK:-/tmp/fc-spike}"
PASS=0; FAIL=0
ok()   { echo "PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

[ -e /dev/kvm ] && ok "/dev/kvm present (KVM-capable host)" || { bad "/dev/kvm absent — cannot boot a microVM here"; echo "FC SPIKE INCONCLUSIVE"; exit 2; }
[ -x "$FC" ] || { bad "firecracker not executable at $FC (set \$FIRECRACKER)"; echo "FC SPIKE INCOMPLETE"; exit 1; }
BZ="$(readlink -f "$IMG/bzImage" 2>/dev/null || true)"
[ -f "$BZ" ] && ok "deploy bzImage found" || { bad "no deploy bzImage ($IMG/bzImage) — build the wic first"; echo "FC SPIKE INCOMPLETE"; exit 1; }
EV="$(find "$REPO/yocto/build/tmp/work" -path '*scripts/extract-vmlinux' 2>/dev/null | head -1)"
[ -n "$EV" ] || { bad "no kernel scripts/extract-vmlinux in the build tree"; echo "FC SPIKE INCOMPLETE"; exit 1; }

rm -rf "$W"; mkdir -p "$W"

# (1) ELF vmlinux out of the bzImage.
sh "$EV" "$BZ" > "$W/vmlinux" 2>/dev/null
head -c4 "$W/vmlinux" | od -An -tx1 | grep -q "7f 45 4c 46" && ok "extracted an ELF vmlinux from the bzImage" || { bad "extract-vmlinux did not yield an ELF"; echo "FC SPIKE INCOMPLETE"; exit 1; }

# (2) minimal busybox rootfs whose init prints a marker + the guest kernel release.
RT="$W/rootfs"; mkdir -p "$RT/bin" "$RT/proc"
cp "$(command -v busybox)" "$RT/bin/busybox"
for lib in $(ldd "$(command -v busybox)" 2>/dev/null | grep -oE '/[^ ]+\.so[0-9.]*'); do
	mkdir -p "$RT$(dirname "$lib")"; cp -L "$lib" "$RT$lib"
done
ln -sf busybox "$RT/bin/sh"
cat > "$RT/init" <<'EOF'
#!/bin/busybox sh
/bin/busybox mount -t proc proc /proc 2>/dev/null
echo "BULKHEAD-FC-SPIKE-OK guest-kernel=$(/bin/busybox uname -r)"
/bin/busybox sync
/bin/busybox reboot -f
EOF
chmod +x "$RT/init"
dd if=/dev/zero of="$W/rootfs.ext4" bs=1M count=64 status=none
MKFS="$(command -v mkfs.ext4 || echo /sbin/mkfs.ext4)"
"$MKFS" -F -q -d "$RT" "$W/rootfs.ext4"
ok "built a minimal microVM rootfs (busybox init)"

# (3) boot the microVM.
cat > "$W/vm.json" <<EOF
{
  "boot-source": {"kernel_image_path": "$W/vmlinux", "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda init=/init"},
  "drives": [{"drive_id":"rootfs","path_on_host":"$W/rootfs.ext4","is_root_device":true,"is_read_only":false}],
  "machine-config": {"vcpu_count":1,"mem_size_mib":256}
}
EOF
OUT="$(timeout 60 "$FC" --no-api --config-file "$W/vm.json" 2>&1 || true)"
echo "----- guest console -----"; echo "$OUT" | grep -aE "Booting paravirtualized|Mounted root|Run /init|BULKHEAD-FC-SPIKE-OK|exit_code" || true; echo "-------------------------"

# (4) assertions: the marker, a real KVM VM, and a guest kernel distinct from the host's.
echo "$OUT" | grep -q "Booting paravirtualized kernel on KVM" && ok "guest booted under KVM (a real VM, separate kernel)" || bad "no 'Booting paravirtualized kernel on KVM' — not a KVM guest"
GK="$(echo "$OUT" | sed -n 's/.*BULKHEAD-FC-SPIKE-OK guest-kernel=\([^ ]*\).*/\1/p' | head -1)"
[ -n "$GK" ] && ok "the bulkhead Yocto kernel ran as the guest init's kernel (guest-kernel=$GK)" || bad "the in-guest marker was not observed"
HK="$(uname -r)"
[ -n "$GK" ] && [ "$GK" != "$HK" ] && ok "host-surface collapse: guest kernel $GK != host kernel $HK (a genuine separate kernel)" || bad "guest kernel not distinct from host ($GK vs $HK)"
echo "$OUT" | grep -q "exit_code=0" && ok "firecracker exited cleanly (the guest init rebooted)" || bad "firecracker did not exit cleanly"

echo
echo "=== Firecracker hostile-tier spike: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && { echo "FC SPIKE GO"; exit 0; } || { echo "FC SPIKE INCOMPLETE"; exit 1; }
