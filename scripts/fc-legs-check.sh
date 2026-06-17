#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# ADR-0042 Firecracker hostile-tier mediated channel — SLICE 1 (the load-bearing reachability proof).
# Proves, on a KVM-capable build host, that an agent inside a no-network microVM can reach a host UNIX
# endpoint ONLY through the provisioned vsock leg, and nothing else:
#   host:  bulkhead-fc-vsockmux stub  (a UNIX endpoint speaking the proxy CONNECT contract: read a line, OK)
#          bulkhead-fc-vsockmux serve-host <uds-base> 2222=<stub>   (the per-instance mux: listens on
#          <uds-base>_2222, splices to the stub — firecracker is the vsock CLIENT into that listener)
#   guest: a microVM (vsock stanza {guest_cid:3, uds_path:<uds-base>}, NO network-interfaces) whose init
#          runs the UNCHANGED-binary verifier:  probe 2 2222 ok  (round-trips CONNECT->OK through the mux),
#          probe 2 9999 reset (an UNPROVISIONED port is refused — reachable set = only what we provision),
#          nonic (no NIC / no direct egress — the device-model half of no-direct-network).
# Host-side only by necessity: the qemu verify suite runs -cpu IvyBridge with no nested KVM, so the
# microVM is proven on the build host (which has /dev/kvm). Exits 2 INCONCLUSIVE where /dev/kvm is absent.
set -eu

FC="${FIRECRACKER:-/home/work/bin/firecracker}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMG="$REPO/yocto/build/tmp/deploy/images/qemux86-64"
W="${FC_LEGS_WORK:-/tmp/fc-legs}"
PASS=0; FAIL=0
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

[ -e /dev/kvm ] && ok "/dev/kvm present" || { echo "FC LEGS INCONCLUSIVE (no /dev/kvm)"; exit 2; }
[ -x "$FC" ] || { bad "firecracker not executable at $FC"; echo "FC LEGS INCOMPLETE"; exit 1; }
BZ="$(readlink -f "$IMG/bzImage" 2>/dev/null || true)"; [ -f "$BZ" ] || { bad "no deploy bzImage — build the wic"; echo "FC LEGS INCOMPLETE"; exit 1; }
EV="$(find "$REPO/yocto/build/tmp/work" -path '*scripts/extract-vmlinux' 2>/dev/null | head -1)"; [ -n "$EV" ] || { bad "no extract-vmlinux"; echo "FC LEGS INCOMPLETE"; exit 1; }

rm -rf "$W"; mkdir -p "$W"
sh "$EV" "$BZ" > "$W/vmlinux" 2>/dev/null
head -c4 "$W/vmlinux" | od -An -tx1 | grep -q "7f 45 4c 46" && ok "extracted ELF vmlinux" || { bad "no ELF vmlinux"; echo "FC LEGS INCOMPLETE"; exit 1; }

# Build the mux: native (host) + a static linux/amd64 binary for the guest (pure Go, CGO off => runs on
# the Yocto guest kernel with no libc dependency).
( cd "$REPO/src/fc-vsockmux" && go build -o "$W/fc-vsockmux" . ) || { bad "host mux build"; echo "FC LEGS INCOMPLETE"; exit 1; }
( cd "$REPO/src/fc-vsockmux" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$W/fc-vsockmux.guest" . ) || { bad "guest mux build"; echo "FC LEGS INCOMPLETE"; exit 1; }
ok "built host + static guest fc-vsockmux"

# Guest rootfs: busybox + the static guest mux + an init running the three verifiers.
RT="$W/rootfs"; mkdir -p "$RT/bin" "$RT/proc"
cp "$(command -v busybox)" "$RT/bin/busybox"
for lib in $(ldd "$(command -v busybox)" 2>/dev/null | grep -oE '/[^ ]+\.so[0-9.]*'); do
	mkdir -p "$RT$(dirname "$lib")"; cp -L "$lib" "$RT$lib"
done
cp "$W/fc-vsockmux.guest" "$RT/bin/fc-vsockmux"
ln -sf busybox "$RT/bin/sh"
cat > "$RT/init" <<'EOF'
#!/bin/busybox sh
/bin/busybox mount -t proc proc /proc 2>/dev/null
echo "FC-LEGS-BEGIN"
/bin/fc-vsockmux probe 2 2222 ok    || echo "PROBE-OK-LEG-FAILED"
/bin/fc-vsockmux probe 2 9999 reset || echo "PROBE-RESET-FAILED"
/bin/fc-vsockmux nonic              || echo "NONIC-FAILED"
echo "FC-LEGS-END"
/bin/busybox sync
/bin/busybox reboot -f
EOF
chmod +x "$RT/init"
dd if=/dev/zero of="$W/rootfs.ext4" bs=1M count=64 status=none
"$(command -v mkfs.ext4 || echo /sbin/mkfs.ext4)" -F -q -d "$RT" "$W/rootfs.ext4"
ok "built guest rootfs (probe init)"

# Host side: a fresh per-instance dir, the stub endpoint, and the mux (LISTENING before the guest dials —
# firecracker is the client for guest-initiated vsock; mux-not-yet-bound => the guest's connect would reset).
UDS="$W/inst/vsock.uds"; mkdir -p "$W/inst"; chmod 700 "$W/inst"
"$W/fc-vsockmux" stub "$W/stub.sock" & STUB=$!
sleep 0.3
"$W/fc-vsockmux" serve-host "$UDS" "2222=$W/stub.sock" & MUX=$!
sleep 0.3
[ -S "${UDS}_2222" ] && ok "mux is listening on the provisioned leg (<uds>_2222) before boot" || bad "mux leg socket not bound"

cat > "$W/vm.json" <<EOF
{
  "boot-source": {"kernel_image_path": "$W/vmlinux", "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda init=/init"},
  "drives": [{"drive_id":"rootfs","path_on_host":"$W/rootfs.ext4","is_root_device":true,"is_read_only":false}],
  "vsock": {"guest_cid": 3, "uds_path": "$UDS"},
  "machine-config": {"vcpu_count":1,"mem_size_mib":256}
}
EOF
echo "=== boot microVM (no network-interfaces stanza => no NIC) ==="
OUT="$(timeout 60 "$FC" --no-api --config-file "$W/vm.json" 2>&1 || true)"
kill "$MUX" "$STUB" 2>/dev/null || true
echo "----- guest output -----"; echo "$OUT" | grep -aE "FC-LEGS-BEGIN|PROBE-OK|PROBE-FAIL|NONIC-OK|NONIC-FAIL|.*-FAILED|FC-LEGS-END" || true; echo "------------------------"

echo "$OUT" | grep -q "PROBE-OK: (2,2222) round-tripped a CONNECT through the mux" && ok "guest reached the host endpoint THROUGH the vsock leg + mux (CONNECT->OK)" || bad "the provisioned-leg round-trip did not succeed"
echo "$OUT" | grep -q "PROBE-OK: (2,9999) refused as expected" && ok "an UNPROVISIONED vsock port is REFUSED (reachable set = only provisioned legs)" || bad "an unprovisioned port was NOT refused (over-reach!)"
echo "$OUT" | grep -q "NONIC-OK: no routable NIC" && ok "the guest has NO NIC / no direct network egress (device-model half)" || bad "the guest had a NIC / direct egress"

echo
echo "=== Firecracker mediated-legs SLICE 1: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && { echo "FC LEGS GO"; exit 0; } || { echo "FC LEGS INCOMPLETE"; exit 1; }
