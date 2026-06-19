#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# ADR-0042 Firecracker hostile-tier — TWO-INSTANCE cross-isolation under the jailer, LIVE on real /dev/kvm
# (checklist [80]). The single-instance proof (fc-jailer-check) shows ONE jailed VMM is non-root + chrooted;
# this proves two concurrent hostile tenants are ISOLATED from each other on the host: distinct per-instance
# non-root uids, distinct chroots, and each jail dir is mode-0700 owned by its own uid — so a compromised
# VMM-A (uid 10000) cannot read VMM-B's jail (uid 10001) and vice versa. Both microVMs boot on real KVM.
# Needs real /dev/kvm + the docker group (root context). Exits 2 INCONCLUSIVE without them.
set -eu

FC="${FIRECRACKER:-/home/work/bin/firecracker}"
JAILER="${JAILER:-/home/work/bin/jailer}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMG="$REPO/yocto/build/tmp/deploy/images/qemux86-64"
W="${FC_JAILER_WORK:-$HOME/.fc-jailer-iso-work}"
PASS=0; FAIL=0
ok()  { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

[ -e /dev/kvm ] && ok "/dev/kvm present (real hardware virtualization)" || { echo "FC JAILER-ISO INCONCLUSIVE (no /dev/kvm)"; exit 2; }
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || { echo "FC JAILER-ISO INCONCLUSIVE (no docker root context)"; exit 2; }
[ -x "$FC" ] && [ -x "$JAILER" ] || { bad "firecracker/jailer not executable"; echo "FC JAILER-ISO INCOMPLETE"; exit 1; }
BZ="$(readlink -f "$IMG/bzImage" 2>/dev/null || true)"; [ -f "$BZ" ] || { bad "no deploy bzImage"; echo "FC JAILER-ISO INCOMPLETE"; exit 1; }
EV="$(find "$REPO/yocto/build/tmp/work" -path '*scripts/extract-vmlinux' 2>/dev/null | head -1)"; [ -n "$EV" ] || { bad "no extract-vmlinux"; echo "FC JAILER-ISO INCOMPLETE"; exit 1; }

rm -rf "$W" 2>/dev/null || true
[ -e "$W" ] && docker run --rm -v "$(dirname "$W")":/p busybox rm -rf "/p/$(basename "$W")" >/dev/null 2>&1 || true
mkdir -p "$W"
sh "$EV" "$BZ" > "$W/vmlinux" 2>/dev/null
head -c4 "$W/vmlinux" | od -An -tx1 | grep -q "7f 45 4c 46" && ok "extracted ELF vmlinux" || { bad "no ELF vmlinux"; echo "FC JAILER-ISO INCOMPLETE"; exit 1; }
cp "$FC" "$W/firecracker"; cp "$JAILER" "$W/jailer"

RT="$W/rootfs"; mkdir -p "$RT/bin" "$RT/proc" "$RT/dev"
cp "$(command -v busybox)" "$RT/bin/busybox"
for lib in $(ldd "$(command -v busybox)" 2>/dev/null | grep -oE '/[^ ]+\.so[0-9.]*'); do mkdir -p "$RT$(dirname "$lib")"; cp -L "$lib" "$RT$lib"; done
ln -sf busybox "$RT/bin/sh"
printf '#!/bin/busybox sh\n/bin/busybox mount -t proc proc /proc 2>/dev/null\necho FC-JAIL-GUEST-UP\n/bin/busybox sleep 8\n/bin/busybox reboot -f\n' > "$RT/init"
chmod +x "$RT/init"
dd if=/dev/zero of="$W/rootfs.ext4" bs=1M count=64 status=none
"$(command -v mkfs.ext4 || echo /sbin/mkfs.ext4)" -F -q -d "$RT" "$W/rootfs.ext4"
ok "built guest rootfs + vmlinux"

cat > "$W/iso-run.sh" <<'CEOF'
#!/bin/sh
set -u
BASE=/work/jail; rm -rf "$BASE"; GJ="$(stat -c %g /dev/kvm)"
launch() { # <id> <uid>
  ID=$1; UJ=$2; R="$BASE/firecracker/$ID/root"
  mkdir -p "$R"; cp /work/vmlinux "$R/vmlinux"; cp /work/rootfs.ext4 "$R/rootfs.ext4"
  printf '{"boot-source":{"kernel_image_path":"/vmlinux","boot_args":"console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda init=/init"},"drives":[{"drive_id":"rootfs","path_on_host":"/rootfs.ext4","is_root_device":true,"is_read_only":false}],"machine-config":{"vcpu_count":1,"mem_size_mib":128}}\n' > "$R/vm.json"
  chown -R "$UJ:$GJ" "$R"
  /work/jailer --id "$ID" --uid "$UJ" --gid "$GJ" --chroot-base-dir "$BASE" --cgroup-version 2 --exec-file /work/firecracker -- --no-api --config-file /vm.json > "/work/$ID.log" 2>&1 &
}
launch fcjail-a 10000
launch fcjail-b 10001
for ID in fcjail-a fcjail-b; do i=0; while [ $i -lt 60 ]; do grep -q FC-JAIL-GUEST-UP "/work/$ID.log" 2>/dev/null && break; sleep 0.5; i=$((i + 1)); done; done
echo "GUESTUP_A=$(grep -c FC-JAIL-GUEST-UP /work/fcjail-a.log 2>/dev/null || echo 0)"
echo "GUESTUP_B=$(grep -c FC-JAIL-GUEST-UP /work/fcjail-b.log 2>/dev/null || echo 0)"
# the two running firecracker VMMs, identified by their jailed uid
for c in /proc/[0-9]*/comm; do
  [ "$(cat "$c" 2>/dev/null)" = firecracker ] || continue
  d="${c%/comm}"; p="${d#/proc/}"; u="$(awk '/^Uid:/{print $2}' "$d/status" 2>/dev/null)"
  echo "VMM uid=$u root=$([ -e "$d/root/vmlinux" ] && echo jail || echo other)"
done
# the per-instance jail dirs: each must be mode 0700 owned by its own uid (=> mutually inaccessible).
echo "DIR_A=$(stat -c '%a %u' "$BASE/firecracker/fcjail-a/root" 2>/dev/null)"
echo "DIR_B=$(stat -c '%a %u' "$BASE/firecracker/fcjail-b/root" 2>/dev/null)"
pkill -f /work/firecracker 2>/dev/null; sleep 1; pkill -9 -f /work/firecracker 2>/dev/null || true
rm -rf "$BASE" 2>/dev/null || true
echo ISO-DONE
CEOF

echo "=== boot TWO jailed microVMs (distinct uids/chroots) on real /dev/kvm ==="
OUT="$(timeout 150 docker run --rm --privileged --cgroupns=host --device /dev/kvm -v "$W":/work busybox sh /work/iso-run.sh 2>&1 || true)"
echo "$OUT" | grep -aE 'GUESTUP_|VMM uid=|DIR_|panic|error' | head -16

g() { echo "$OUT" | grep -aE "^$1=" | head -1 | cut -d= -f2-; }
[ "$(g GUESTUP_A)" -ge 1 ] 2>/dev/null && [ "$(g GUESTUP_B)" -ge 1 ] 2>/dev/null && ok "BOTH jailed microVMs booted on real KVM" || bad "one or both microVMs did not boot"
UIDS="$(echo "$OUT" | grep -aoE 'uid=[0-9]+' | sort -u | tr '\n' ' ')"
case "$UIDS" in *uid=10000*uid=10001*) ok "the two VMMs run as DISTINCT non-root uids (10000, 10001)" ;; *) bad "VMM uids not distinct/non-root: $UIDS" ;; esac
NJAIL="$(echo "$OUT" | grep -ac 'root=jail')"
[ "$NJAIL" -ge 2 ] && ok "both VMMs are chrooted into their own jail (root=jail x2)" || bad "VMMs not both chrooted ($NJAIL)"
DA="$(g DIR_A)"; DB="$(g DIR_B)"
case "$DA" in "700 10000") A_ISO=1 ;; *) A_ISO=0 ;; esac
case "$DB" in "700 10001") B_ISO=1 ;; *) B_ISO=0 ;; esac
[ "$A_ISO" = 1 ] && [ "$B_ISO" = 1 ] && ok "each jail dir is mode-0700 owned by its OWN uid (A:$DA B:$DB) — VMM-A (10000) cannot read VMM-B's jail, and vice versa" || bad "jail dirs not per-uid-0700 isolated (A:'$DA' B:'$DB')"

echo
echo "=== Firecracker JAILER 2-instance cross-isolation (real KVM): $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && { echo "FC JAILER-ISO GO"; exit 0; } || { echo "FC JAILER-ISO INCOMPLETE"; exit 1; }
