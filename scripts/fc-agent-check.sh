#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# ADR-0042 Firecracker hostile-tier mediated channel — SLICE 2: the UNCHANGED bulkhead-agent binary reaches
# the host ONLY through its UNIX legs, backed by the in-guest vsock forwarder. This proves the load-bearing
# claim that the agent is byte-identical across tiers (the runsc --host-uds precedent): in the microVM the
# agent still net.Dial("unix", $BULKHEAD_EGRESS_SOCK); bulkhead-vsock-legs (fc-vsockmux serve-guest) presents
# that UNIX socket and splices it over vsock to the per-instance host mux -> the (stub here, real in slice 3)
# egress endpoint. Asserts the real `bulkhead-agent probe-egress`:
#   NOROUTE  PASS — a direct dial to a public IP fails (no NIC in the VM);
#   ISOLATED PASS — a direct dial to the loopback target fails (not the agent's own loopback);
#   PROXY-OK PASS — the SAME target IS reachable via the mediated UNIX leg (forwarder->vsock->mux->stub).
# (PROXY-DENY / IOURING need the real allowlisted proxy + the FC-tuned io_uring-off guest kernel — slices
# 3/5 — so they are not gated here.) Host-side only (no nested KVM in the qemu suite); exits 2 without /dev/kvm.
set -eu

FC="${FIRECRACKER:-/home/work/bin/firecracker}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMG="$REPO/yocto/build/tmp/deploy/images/qemux86-64"
W="${FC_AGENT_WORK:-/tmp/fc-agent}"
PASS=0; FAIL=0
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

[ -e /dev/kvm ] && ok "/dev/kvm present" || { echo "FC AGENT INCONCLUSIVE (no /dev/kvm)"; exit 2; }
[ -x "$FC" ] || { bad "firecracker not executable at $FC"; echo "FC AGENT INCOMPLETE"; exit 1; }
BZ="$(readlink -f "$IMG/bzImage" 2>/dev/null || true)"; [ -f "$BZ" ] || { bad "no deploy bzImage"; echo "FC AGENT INCOMPLETE"; exit 1; }
EV="$(find "$REPO/yocto/build/tmp/work" -path '*scripts/extract-vmlinux' 2>/dev/null | head -1)"; [ -n "$EV" ] || { bad "no extract-vmlinux"; echo "FC AGENT INCOMPLETE"; exit 1; }

rm -rf "$W"; mkdir -p "$W"
sh "$EV" "$BZ" > "$W/vmlinux" 2>/dev/null
head -c4 "$W/vmlinux" | od -An -tx1 | grep -q "7f 45 4c 46" && ok "extracted ELF vmlinux" || { bad "no ELF vmlinux"; echo "FC AGENT INCOMPLETE"; exit 1; }

# Build the host mux (native), the static guest mux (forwarder), and the UNCHANGED agent (static, guest).
( cd "$REPO/src/fc-vsockmux" && go build -o "$W/fc-vsockmux" . ) || { bad "host mux build"; echo "FC AGENT INCOMPLETE"; exit 1; }
( cd "$REPO/src/fc-vsockmux" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$W/fc-vsockmux.guest" . ) || { bad "guest mux build"; echo "FC AGENT INCOMPLETE"; exit 1; }
( cd "$REPO/src/agent" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$W/bulkhead-agent.guest" . ) || { bad "guest agent build"; echo "FC AGENT INCOMPLETE"; exit 1; }
ok "built host mux + static guest forwarder + the UNCHANGED static agent"

# Guest rootfs: busybox + the static guest mux (forwarder) + the unchanged agent + an init that starts the
# forwarder, waits for the leg, then runs the REAL agent probe with its leg pointed at the forwarder's UNIX socket.
RT="$W/rootfs"; mkdir -p "$RT/bin" "$RT/proc" "$RT/run" "$RT/dev"
cp "$(command -v busybox)" "$RT/bin/busybox"
for lib in $(ldd "$(command -v busybox)" 2>/dev/null | grep -oE '/[^ ]+\.so[0-9.]*'); do
	mkdir -p "$RT$(dirname "$lib")"; cp -L "$lib" "$RT$lib"
done
cp "$W/fc-vsockmux.guest" "$RT/bin/fc-vsockmux"
cp "$W/bulkhead-agent.guest" "$RT/bin/bulkhead-agent"
ln -sf busybox "$RT/bin/sh"
cat > "$RT/init" <<'EOF'
#!/bin/busybox sh
/bin/busybox mount -t proc proc /proc 2>/dev/null
/bin/busybox mount -t devtmpfs dev /dev 2>/dev/null   # /dev/null is needed: busybox backgrounds bg-jobs' stdin from it
/bin/busybox mkdir -p /run/bulkhead-egress /run/bulkhead-router
# the in-guest forwarder presents the agent's expected UNIX legs, bridged over vsock to the host mux
/bin/fc-vsockmux serve-guest /run/bulkhead-egress/egress.sock=2222 /run/bulkhead-router/router.sock=2223 &
for i in $(/bin/busybox seq 1 30); do [ -S /run/bulkhead-egress/egress.sock ] && break; /bin/busybox sleep 1; done
[ -S /run/bulkhead-egress/egress.sock ] && echo "FWD-LEG-UP" || echo "FWD-LEG-MISSING"
echo "FC-AGENT-BEGIN"
BULKHEAD_EGRESS_SOCK=/run/bulkhead-egress/egress.sock \
BULKHEAD_ROUTER_UDS=/run/bulkhead-router/router.sock \
  /bin/bulkhead-agent probe-egress
echo "FC-AGENT-END"
/bin/busybox sync
/bin/busybox reboot -f
EOF
chmod +x "$RT/init"
dd if=/dev/zero of="$W/rootfs.ext4" bs=1M count=64 status=none
"$(command -v mkfs.ext4 || echo /sbin/mkfs.ext4)" -F -q -d "$RT" "$W/rootfs.ext4"
ok "built guest rootfs (forwarder + unchanged agent)"

# Host: a stub speaking the proxy CONNECT contract + the mux LISTENING on both legs before boot.
UDS="$W/inst/vsock.uds"; mkdir -p "$W/inst"; chmod 700 "$W/inst"
"$W/fc-vsockmux" stub "$W/stub.sock" & STUB=$!
sleep 0.3
"$W/fc-vsockmux" serve-host "$UDS" "2222=$W/stub.sock" "2223=$W/stub.sock" & MUX=$!
sleep 0.3
[ -S "${UDS}_2222" ] && ok "mux listening on both legs before boot" || bad "mux leg socket not bound"

cat > "$W/vm.json" <<EOF
{
  "boot-source": {"kernel_image_path": "$W/vmlinux", "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda init=/init"},
  "drives": [{"drive_id":"rootfs","path_on_host":"$W/rootfs.ext4","is_root_device":true,"is_read_only":false}],
  "vsock": {"guest_cid": 3, "uds_path": "$UDS"},
  "machine-config": {"vcpu_count":1,"mem_size_mib":256}
}
EOF
echo "=== boot microVM (unchanged agent, no network-interfaces stanza) ==="
OUT="$(timeout 90 "$FC" --no-api --config-file "$W/vm.json" 2>&1 || true)"
kill "$MUX" "$STUB" 2>/dev/null || true
echo "----- agent probe output -----"; echo "$OUT" | grep -aE "FC-AGENT-BEGIN|PROBE (NOROUTE|ISOLATED|PROXY-OK|PROXY-DENY|IOURING)|FC-AGENT-END" || true; echo "------------------------------"

echo "$OUT" | grep -q "PROBE NOROUTE: PASS" && ok "unchanged agent: NOROUTE PASS (no direct route in the VM)" || bad "NOROUTE did not pass"
echo "$OUT" | grep -q "PROBE ISOLATED: PASS" && ok "unchanged agent: ISOLATED PASS (loopback target not directly reachable)" || bad "ISOLATED did not pass"
echo "$OUT" | grep -q "PROBE PROXY-OK: PASS" && ok "unchanged agent reached the host via its UNIX leg -> forwarder -> vsock -> mux (PROXY-OK)" || bad "PROXY-OK did not pass — the mediated leg did not carry the unchanged agent"

echo
echo "=== Firecracker mediated-legs SLICE 2: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && { echo "FC AGENT GO"; exit 0; } || { echo "FC AGENT INCOMPLETE"; exit 1; }
