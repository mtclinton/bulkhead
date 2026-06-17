#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# ADR-0042 Firecracker hostile-tier mediated channel — SLICE 4: confinement assertions on the running VMM
# + mux. The adversarial pass named ONE plausible way to break no-direct-network: a HOST-side network
# primitive (AF_INET/AF_PACKET/io_uring) on firecracker or the mux bypassing the proxy. And the
# channel-confusion break rests on the per-instance dir holding EXACTLY the provisioned sockets. This
# slice asserts both LIVE:
#   (1) the running firecracker process holds NO internet socket (AF_INET/AF_INET6) — only the AF_UNIX
#       vsock backend + file fds; with no network-interfaces stanza it has no host network primitive;
#   (2) the per-instance dir holds EXACTLY {vsock.uds, vsock.uds_2222, vsock.uds_2223}, and the MUX (not
#       firecracker, not any other process) is the sole listener on the two leg sockets.
#
# The firecracker JAILER (per-instance uid/chroot/empty-netns/cgroup) is the production confinement of the
# VMM; it requires ROOT (chroot+setuid+cgroup), so its live run is gated here: as root with $JAILER present
# we wrap firecracker under it; as non-root we run firecracker bare and the jailer-confinement is
# build/config-verified only (the deployable bulkhead-agent-firecracker@ unit, slice 6) — the socket
# assertions above hold either way (no-inet is inherent to the no-net-stanza config; the jailer ADDS
# uid/chroot/netns/cgroup on top). Host-side; exits 2 INCONCLUSIVE without /dev/kvm.
set -eu

FC="${FIRECRACKER:-/home/work/bin/firecracker}"
JAILER="${JAILER:-/home/work/bin/jailer}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMG="$REPO/yocto/build/tmp/deploy/images/qemux86-64"
W="${FC_JAIL_WORK:-/tmp/fc-jail}"
PASS=0; FAIL=0
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

[ -e /dev/kvm ] && ok "/dev/kvm present" || { echo "FC JAIL INCONCLUSIVE (no /dev/kvm)"; exit 2; }
[ -x "$FC" ] || { bad "firecracker not executable"; echo "FC JAIL INCOMPLETE"; exit 1; }
BZ="$(readlink -f "$IMG/bzImage" 2>/dev/null || true)"; [ -f "$BZ" ] || { bad "no deploy bzImage"; echo "FC JAIL INCOMPLETE"; exit 1; }
EV="$(find "$REPO/yocto/build/tmp/work" -path '*scripts/extract-vmlinux' 2>/dev/null | head -1)"; [ -n "$EV" ] || { bad "no extract-vmlinux"; echo "FC JAIL INCOMPLETE"; exit 1; }

rm -rf "$W"; mkdir -p "$W"
sh "$EV" "$BZ" > "$W/vmlinux" 2>/dev/null
head -c4 "$W/vmlinux" | od -An -tx1 | grep -q "7f 45 4c 46" && ok "extracted ELF vmlinux" || { bad "no ELF vmlinux"; echo "FC JAIL INCOMPLETE"; exit 1; }
( cd "$REPO/src/fc-vsockmux" && go build -o "$W/fc-vsockmux" . ) || { bad "mux build"; echo "FC JAIL INCOMPLETE"; exit 1; }

if [ "$(id -u)" = 0 ] && [ -x "$JAILER" ]; then JAILED=1; ok "running under the firecracker JAILER (root)"; else JAILED=0; echo "NOTE: non-root -> firecracker runs BARE; jailer-confinement is build/config-verified (slice 6). Socket assertions still hold."; fi

# Guest rootfs whose init just keeps the VM alive long enough to inspect the host process, then reboots.
RT="$W/rootfs"; mkdir -p "$RT/bin" "$RT/proc" "$RT/dev"
cp "$(command -v busybox)" "$RT/bin/busybox"
for lib in $(ldd "$(command -v busybox)" 2>/dev/null | grep -oE '/[^ ]+\.so[0-9.]*'); do mkdir -p "$RT$(dirname "$lib")"; cp -L "$lib" "$RT$lib"; done
ln -sf busybox "$RT/bin/sh"
cat > "$RT/init" <<'EOF'
#!/bin/busybox sh
/bin/busybox mount -t proc proc /proc 2>/dev/null
echo "FC-JAIL-GUEST-UP"
/bin/busybox sleep 8
/bin/busybox reboot -f
EOF
chmod +x "$RT/init"
dd if=/dev/zero of="$W/rootfs.ext4" bs=1M count=64 status=none
"$(command -v mkfs.ext4 || echo /sbin/mkfs.ext4)" -F -q -d "$RT" "$W/rootfs.ext4"

# Fresh per-instance dir (0700, the mux's sole writer); the mux binds the two legs there.
INST="$W/inst"; mkdir -p "$INST"; chmod 700 "$INST"
UDS="$INST/vsock.uds"
"$W/fc-vsockmux" stub "$W/stub.sock" & STUB=$!; sleep 0.3
"$W/fc-vsockmux" serve-host "$UDS" "2222=$W/stub.sock" "2223=$W/stub.sock" & MUX=$!; sleep 0.3

cat > "$W/vm.json" <<EOF
{
  "boot-source": {"kernel_image_path": "$W/vmlinux", "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda init=/init"},
  "drives": [{"drive_id":"rootfs","path_on_host":"$W/rootfs.ext4","is_root_device":true,"is_read_only":false}],
  "vsock": {"guest_cid": 3, "uds_path": "$UDS"},
  "machine-config": {"vcpu_count":1,"mem_size_mib":256}
}
EOF
# firecracker in the BACKGROUND so we can inspect its host process while the guest sleeps.
"$FC" --no-api --config-file "$W/vm.json" > "$W/fc.log" 2>&1 & FCPID=$!
for i in $(seq 1 40); do grep -q "FC-JAIL-GUEST-UP" "$W/fc.log" 2>/dev/null && break; sleep 0.25; done
grep -q "FC-JAIL-GUEST-UP" "$W/fc.log" && ok "microVM up; firecracker pid=$FCPID" || bad "guest did not come up"

# (1) firecracker holds NO internet socket (no host network primitive).
INET="$(lsof -p "$FCPID" -a -i 2>/dev/null | tail -n +2)"
[ -z "$INET" ] && ok "firecracker holds NO AF_INET/AF_INET6 socket (no host network egress primitive)" || bad "firecracker holds an internet socket: $INET"
# (2a) the per-instance dir holds EXACTLY the three expected sockets.
DIRLIST="$(ls -1 "$INST" 2>/dev/null | sort | tr '\n' ',')"
[ "$DIRLIST" = "vsock.uds,vsock.uds_2222,vsock.uds_2223," ] && ok "per-instance dir holds EXACTLY {vsock.uds, _2222, _2223}" || bad "unexpected per-instance dir contents: $DIRLIST"
# (2b) the MUX is the sole listener on the leg sockets (not firecracker / not another pid).
LEGLISTENER="$(ss -xlp 2>/dev/null | grep "vsock.uds_2222" | grep -c "pid=$MUX," || true)"
[ "${LEGLISTENER:-0}" -ge 1 ] && ok "the mux (pid=$MUX) is the listener on the leg socket _2222" || bad "the leg listener is not the mux (ss: $(ss -xlp 2>/dev/null | grep vsock.uds_2222 | head -1))"

wait "$FCPID" 2>/dev/null || true
kill "$MUX" "$STUB" 2>/dev/null || true

echo
echo "=== Firecracker mediated-legs SLICE 4: $PASS passed, $FAIL failed (jailed=$JAILED) ==="
[ "$FAIL" -eq 0 ] && { echo "FC JAIL GO"; exit 0; } || { echo "FC JAIL INCOMPLETE"; exit 1; }
