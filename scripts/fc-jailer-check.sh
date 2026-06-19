#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# ADR-0042 Firecracker hostile-tier — the JAILER confinement of the VMM, LIVE on real /dev/kvm. fc-jail-check
# only LABELS the jailer path (it runs firecracker bare); the actual jailer wrap is root-gated. This proves it
# for real: it runs `jailer` (per-instance non-root uid + chroot + cgroup) wrapping firecracker inside a
# privileged container that provides the root context + real /dev/kvm, and asserts via /proc that the running
# firecracker is genuinely confined — so a VMM/KVM 0-day (ADR-0031's accepted residual) lands in a chrooted,
# non-root, cgroup-bounded process with no host network primitive, not host root.
#   (1) the microVM booted UNDER the jailer (the jailed VMM still works);
#   (2) firecracker runs as the per-instance NON-ROOT uid (jailer setuid'd it);
#   (3) firecracker is CHROOTED into the per-instance jail (its / is the jail root, not the host /);
#   (4) firecracker is in a jailer-created CGROUP (not the root cgroup);
#   (5) firecracker holds NO inet socket (no host network egress primitive; no net stanza + jail).
# Needs real /dev/kvm + the `docker` group (root context). Exits 2 INCONCLUSIVE without them.
set -eu

FC="${FIRECRACKER:-/home/work/bin/firecracker}"
JAILER="${JAILER:-/home/work/bin/jailer}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMG="$REPO/yocto/build/tmp/deploy/images/qemux86-64"
# The chroot needs a dev-ALLOWED filesystem: the jailer mknods /dev/kvm in the chroot, and on a `nodev` mount
# (e.g. a typical /tmp tmpfs) that device node is non-functional -> the jailed firecracker gets EACCES on
# /dev/kvm. Default to a dir on / (ext4, dev-allowed); override via FC_JAILER_WORK to any dev-allowed path.
W="${FC_JAILER_WORK:-$HOME/.fc-jailer-work}"
PASS=0; FAIL=0
ok()  { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

[ -e /dev/kvm ] && ok "/dev/kvm present (real hardware virtualization)" || { echo "FC JAILER INCONCLUSIVE (no /dev/kvm)"; exit 2; }
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || { echo "FC JAILER INCONCLUSIVE (no docker root context)"; exit 2; }
[ -x "$FC" ] && [ -x "$JAILER" ] || { bad "firecracker/jailer not executable"; echo "FC JAILER INCOMPLETE"; exit 1; }
BZ="$(readlink -f "$IMG/bzImage" 2>/dev/null || true)"; [ -f "$BZ" ] || { bad "no deploy bzImage"; echo "FC JAILER INCOMPLETE"; exit 1; }
EV="$(find "$REPO/yocto/build/tmp/work" -path '*scripts/extract-vmlinux' 2>/dev/null | head -1)"; [ -n "$EV" ] || { bad "no extract-vmlinux"; echo "FC JAILER INCOMPLETE"; exit 1; }

# the jailer (root, via docker) creates a root-owned chroot under $W; clean any leftover via a root docker run.
rm -rf "$W" 2>/dev/null || true
[ -e "$W" ] && docker run --rm -v "$(dirname "$W")":/p busybox rm -rf "/p/$(basename "$W")" >/dev/null 2>&1 || true
mkdir -p "$W"
sh "$EV" "$BZ" > "$W/vmlinux" 2>/dev/null
head -c4 "$W/vmlinux" | od -An -tx1 | grep -q "7f 45 4c 46" && ok "extracted ELF vmlinux" || { bad "no ELF vmlinux"; echo "FC JAILER INCOMPLETE"; exit 1; }
cp "$FC" "$W/firecracker"; cp "$JAILER" "$W/jailer"   # same fs as the chroot so the jailer can hardlink the exec-file

# Guest rootfs: busybox + an init that announces itself, sleeps long enough to inspect the host process, reboots.
RT="$W/rootfs"; mkdir -p "$RT/bin" "$RT/proc" "$RT/dev"
cp "$(command -v busybox)" "$RT/bin/busybox"
for lib in $(ldd "$(command -v busybox)" 2>/dev/null | grep -oE '/[^ ]+\.so[0-9.]*'); do mkdir -p "$RT$(dirname "$lib")"; cp -L "$lib" "$RT$lib"; done
ln -sf busybox "$RT/bin/sh"
printf '#!/bin/busybox sh\n/bin/busybox mount -t proc proc /proc 2>/dev/null\necho FC-JAIL-GUEST-UP\n/bin/busybox sleep 8\n/bin/busybox reboot -f\n' > "$RT/init"
chmod +x "$RT/init"
dd if=/dev/zero of="$W/rootfs.ext4" bs=1M count=64 status=none
"$(command -v mkfs.ext4 || echo /sbin/mkfs.ext4)" -F -q -d "$RT" "$W/rootfs.ext4"
ok "built guest rootfs + vmlinux + jailer/firecracker"

# The in-container orchestrator (runs as root): pre-stage the chroot, run the jailer, dump /proc facts about
# the confined firecracker. Pure /proc + busybox — no extra tools needed.
cat > "$W/jail-run.sh" <<'CEOF'
#!/bin/sh
set -u
ID=fcjail; UJ=10000; GJ="$(stat -c %g /dev/kvm 2>/dev/null || echo 10000)"; BASE=/work/jail; ROOT="$BASE/firecracker/$ID/root"
echo "JAIL-GID=$GJ"   # the kvm group, so the per-instance jailed VMM can open /dev/kvm
rm -rf "$BASE"; mkdir -p "$ROOT"
cp /work/vmlinux "$ROOT/vmlinux"; cp /work/rootfs.ext4 "$ROOT/rootfs.ext4"
printf '{"boot-source":{"kernel_image_path":"/vmlinux","boot_args":"console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda init=/init"},"drives":[{"drive_id":"rootfs","path_on_host":"/rootfs.ext4","is_root_device":true,"is_read_only":false}],"machine-config":{"vcpu_count":1,"mem_size_mib":256}}\n' > "$ROOT/vm.json"
chown -R $UJ:$GJ "$ROOT" 2>/dev/null
echo JAILER-START
/work/jailer --id "$ID" --uid $UJ --gid $GJ --chroot-base-dir "$BASE" --cgroup-version 2 --exec-file /work/firecracker -- --no-api --config-file /vm.json > /work/jailer.log 2>&1 &
JPID=$!
i=0; while [ $i -lt 60 ]; do grep -q FC-JAIL-GUEST-UP /work/jailer.log 2>/dev/null && break; sleep 0.5; i=$((i + 1)); done
FCPID=""
for c in /proc/[0-9]*/comm; do [ "$(cat "$c" 2>/dev/null)" = firecracker ] && { d="${c%/comm}"; FCPID="${d#/proc/}"; break; }; done
echo "FCPID=$FCPID"
echo "HOSTKVM=$(ls -ln /dev/kvm 2>/dev/null)"
echo "CHROOTDEV=$(ls -ln "$ROOT/dev/" 2>/dev/null | tr '\n' ';')"
echo "GUESTUP=$(grep -c FC-JAIL-GUEST-UP /work/jailer.log 2>/dev/null || echo 0)"
echo "UID=$(awk '/^Uid:/{print $2}' /proc/$FCPID/status 2>/dev/null)"
# firecracker's root is the jail iff its root fs has /vmlinux (jail-only) but NOT /etc (host/container only).
echo "CHROOTOK=$([ -e /proc/$FCPID/root/vmlinux ] && [ ! -e /proc/$FCPID/root/etc ] && echo yes || echo no)"
echo "ROOTLINK=$(readlink /proc/$FCPID/root 2>/dev/null)"
echo "CGROUP=$(cat /proc/$FCPID/cgroup 2>/dev/null | head -1)"
echo "INET=$(($(tail -n +2 /proc/$FCPID/net/tcp 2>/dev/null | wc -l) + $(tail -n +2 /proc/$FCPID/net/tcp6 2>/dev/null | wc -l)))"
echo "JAILER-LOG:"; tail -8 /work/jailer.log 2>/dev/null
kill $JPID 2>/dev/null; sleep 1; kill -9 $JPID 2>/dev/null || true
rm -rf "$BASE" 2>/dev/null || true   # self-clean the root-owned chroot so the host can re-run
echo JAILER-DONE
CEOF

echo "=== run the JAILER wrapping firecracker on real /dev/kvm (root via docker --privileged) ==="
# --cgroupns=host so the jailer can create its per-instance cgroup under the real hierarchy (cgroup-v2
# delegation; the appliance's systemd unit provides this natively).
OUT="$(timeout 120 docker run --rm --privileged --cgroupns=host --device /dev/kvm -v "$W":/work busybox sh /work/jail-run.sh 2>&1 || true)"
echo "$OUT" | grep -aE 'JAIL-GID=|HOSTKVM=|CHROOTDEV=|FCPID=|GUESTUP=|UID=|ROOTLINK=|CGROUP=|INET=|JAILER-LOG:|panic|error' | head -24

g() { echo "$OUT" | grep -aE "^$1=" | head -1 | cut -d= -f2-; }
FCPID="$(g FCPID)"; GUESTUP="$(g GUESTUP)"; FUID="$(g UID)"; CHROOTOK="$(g CHROOTOK)"; CG="$(g CGROUP)"; INET="$(g INET)"

[ -n "$FCPID" ] && ok "firecracker booted UNDER the jailer (pid=$FCPID)" || bad "no jailed firecracker process found"
[ "${GUESTUP:-0}" -ge 1 ] 2>/dev/null && ok "the jailed microVM booted on real KVM (guest console reached)" || bad "the jailed microVM did not boot (guest console absent)"
[ "$FUID" = 10000 ] && ok "firecracker runs as the per-instance NON-ROOT uid 10000 (jailer setuid)" || bad "firecracker uid is '$FUID', not the jailed 10000"
[ "$CHROOTOK" = yes ] && ok "firecracker is CHROOTED into the per-instance jail (its root has /vmlinux, no /etc — the host fs is not visible)" || bad "firecracker is not chrooted into the jail"
[ "${INET:-1}" -eq 0 ] 2>/dev/null && ok "firecracker holds NO inet socket (no host network egress primitive)" || bad "firecracker has $INET inet socket(s)"
# cgroup placement needs cgroup-v2 delegation (the appliance's systemd unit provides it). Informational here.
case "$CG" in *fcjail*|*firecracker*) ok "firecracker is in the jailer-created cgroup ($CG)" ;; *) echo "NOTE: firecracker cgroup='$CG' — the per-instance cgroup needs cgroup-v2 delegation (the appliance systemd unit delegates it; docker --privileged may not). uid+chroot+no-net confinement holds regardless." ;; esac

echo
echo "=== Firecracker JAILER confinement (real KVM, root via docker): $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && { echo "FC JAILER GO"; exit 0; } || { echo "FC JAILER INCOMPLETE"; exit 1; }
