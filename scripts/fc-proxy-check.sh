#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# ADR-0042 Firecracker hostile-tier mediated channel — SLICE 3: ADR-0034 policy + the signed audit chain
# hold UNCHANGED over the vsock transport. Swaps slice 2's stub for the REAL bulkhead-egress-proxy on a host
# UNIX socket (allowlist + signed chain), with the mux's egress leg pointed at it. The UNCHANGED agent's
# probe-egress, from inside a no-network microVM, must:
#   PROXY-OK   PASS — an allowlisted destination is reachable via the mediated leg -> forwarder -> vsock ->
#                     mux -> REAL proxy (which signs a record-before-act ALLOW);
#   PROXY-DENY PASS — a NON-allowlisted destination is REFUSED by the real proxy's allowlist (signed DENY).
# Then on the host: the proxy's /data egress chain GREW and `bulkhead-collector verify-audit` PASSES — the
# decisions made over vsock are the same signed, verifiable records the other tiers produce. Host-side only
# (no nested KVM in the qemu suite); exits 2 INCONCLUSIVE without /dev/kvm.
set -eu

FC="${FIRECRACKER:-/home/work/bin/firecracker}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMG="$REPO/yocto/build/tmp/deploy/images/qemux86-64"
W="${FC_PROXY_WORK:-/tmp/fc-proxy}"
PASS=0; FAIL=0
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

[ -e /dev/kvm ] && ok "/dev/kvm present" || { echo "FC PROXY INCONCLUSIVE (no /dev/kvm)"; exit 2; }
[ -x "$FC" ] || { bad "firecracker not executable at $FC"; echo "FC PROXY INCOMPLETE"; exit 1; }
BZ="$(readlink -f "$IMG/bzImage" 2>/dev/null || true)"; [ -f "$BZ" ] || { bad "no deploy bzImage"; echo "FC PROXY INCOMPLETE"; exit 1; }
EV="$(find "$REPO/yocto/build/tmp/work" -path '*scripts/extract-vmlinux' 2>/dev/null | head -1)"; [ -n "$EV" ] || { bad "no extract-vmlinux"; echo "FC PROXY INCOMPLETE"; exit 1; }

rm -rf "$W"; mkdir -p "$W"
sh "$EV" "$BZ" > "$W/vmlinux" 2>/dev/null
head -c4 "$W/vmlinux" | od -An -tx1 | grep -q "7f 45 4c 46" && ok "extracted ELF vmlinux" || { bad "no ELF vmlinux"; echo "FC PROXY INCOMPLETE"; exit 1; }

# Build: host proxy + collector (for verify-audit) + mux; static guest mux (forwarder) + agent.
( cd "$REPO/src/proxy"       && go build -o "$W/bulkhead-egress-proxy" . ) || { bad "proxy build"; echo "FC PROXY INCOMPLETE"; exit 1; }
( cd "$REPO/src/collector"   && go build -o "$W/bulkhead-collector" . )    || { bad "collector build"; echo "FC PROXY INCOMPLETE"; exit 1; }
( cd "$REPO/src/fc-vsockmux" && go build -o "$W/fc-vsockmux" . )           || { bad "host mux build"; echo "FC PROXY INCOMPLETE"; exit 1; }
( cd "$REPO/src/fc-vsockmux" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$W/fc-vsockmux.guest" . ) || { bad "guest mux build"; echo "FC PROXY INCOMPLETE"; exit 1; }
( cd "$REPO/src/agent"       && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$W/bulkhead-agent.guest" . ) || { bad "guest agent build"; echo "FC PROXY INCOMPLETE"; exit 1; }
ok "built host proxy + collector + mux, and the static guest forwarder + UNCHANGED agent"

# Seed + allowlist + audit dir for the REAL proxy (stable seed so verify-audit can re-derive the pubkey).
SEEDDIR="$W/creds"; mkdir -p "$SEEDDIR"; head -c32 /dev/urandom > "$SEEDDIR/audit-seed"
ADIR="$W/audit"; mkdir -p "$ADIR"
printf '127.0.0.1\n' > "$W/allow.conf"
PROXY_SOCK="$W/inst/egress.sock"; mkdir -p "$W/inst"

# Run the REAL egress proxy on the host: loopback allowlist + the 127/8 internal-CIDR allow + signed chain.
BULKHEAD_EGRESS_SOCK="$PROXY_SOCK" \
BULKHEAD_EGRESS_ALLOWLIST="$W/allow.conf" \
BULKHEAD_EGRESS_ALLOW_INTERNAL_CIDRS="127.0.0.0/8" \
BULKHEAD_AUDIT_DIR="$ADIR" \
CREDENTIALS_DIRECTORY="$SEEDDIR" \
  "$W/bulkhead-egress-proxy" > "$W/proxy.log" 2>&1 & PROXY=$!
for i in $(seq 1 30); do [ -S "$PROXY_SOCK" ] && break; sleep 0.2; done
[ -S "$PROXY_SOCK" ] && ok "real egress proxy listening (allowlist + signed chain)" || { bad "proxy did not come up: $(tail -2 "$W/proxy.log" 2>/dev/null)"; kill "$PROXY" 2>/dev/null; echo "FC PROXY INCOMPLETE"; exit 1; }

reccount() { if [ -f "$1" ]; then grep -c . "$1" 2>/dev/null || true; else echo 0; fi; }
REC_BEFORE=$(reccount "$ADIR/provenance.jsonl")

# A bare TCP upstream at the probe target so the proxy's CONNECT->upstream-dial->OK succeeds (the proxy
# replies ERR if its upstream dial fails; the probe only needs the CONNECT to reach OK).
python3 -c 'import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 8088)); s.listen(128)
while True:
    c,_ = s.accept(); c.close()' & UPSTREAM=$!
sleep 0.3

# The mux's egress leg -> the REAL proxy UDS.
UDS="$W/inst/vsock.uds"
"$W/fc-vsockmux" serve-host "$UDS" "2222=$PROXY_SOCK" "2223=$PROXY_SOCK" & MUX=$!
sleep 0.3
[ -S "${UDS}_2222" ] && ok "mux leg -> real proxy bound before boot" || bad "mux leg not bound"

# Guest rootfs: forwarder + UNCHANGED agent probe-egress (devtmpfs needed — busybox bg-job stdin=/dev/null).
RT="$W/rootfs"; mkdir -p "$RT/bin" "$RT/proc" "$RT/run" "$RT/dev"
cp "$(command -v busybox)" "$RT/bin/busybox"
for lib in $(ldd "$(command -v busybox)" 2>/dev/null | grep -oE '/[^ ]+\.so[0-9.]*'); do mkdir -p "$RT$(dirname "$lib")"; cp -L "$lib" "$RT$lib"; done
cp "$W/fc-vsockmux.guest" "$RT/bin/fc-vsockmux"; cp "$W/bulkhead-agent.guest" "$RT/bin/bulkhead-agent"; ln -sf busybox "$RT/bin/sh"
cat > "$RT/init" <<'EOF'
#!/bin/busybox sh
/bin/busybox mount -t proc proc /proc 2>/dev/null
/bin/busybox mount -t devtmpfs dev /dev 2>/dev/null
/bin/busybox mkdir -p /run/bulkhead-egress /run/bulkhead-router
/bin/fc-vsockmux serve-guest /run/bulkhead-egress/egress.sock=2222 /run/bulkhead-router/router.sock=2223 &
for i in $(/bin/busybox seq 1 30); do [ -S /run/bulkhead-egress/egress.sock ] && break; /bin/busybox sleep 1; done
echo "FC-PROXY-BEGIN"
BULKHEAD_EGRESS_SOCK=/run/bulkhead-egress/egress.sock BULKHEAD_ROUTER_UDS=/run/bulkhead-router/router.sock \
  /bin/bulkhead-agent probe-egress
echo "FC-PROXY-END"
/bin/busybox sync
/bin/busybox reboot -f
EOF
chmod +x "$RT/init"
dd if=/dev/zero of="$W/rootfs.ext4" bs=1M count=64 status=none
"$(command -v mkfs.ext4 || echo /sbin/mkfs.ext4)" -F -q -d "$RT" "$W/rootfs.ext4"
ok "built guest rootfs (forwarder + unchanged agent)"

cat > "$W/vm.json" <<EOF
{
  "boot-source": {"kernel_image_path": "$W/vmlinux", "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda init=/init"},
  "drives": [{"drive_id":"rootfs","path_on_host":"$W/rootfs.ext4","is_root_device":true,"is_read_only":false}],
  "vsock": {"guest_cid": 3, "uds_path": "$UDS"},
  "machine-config": {"vcpu_count":1,"mem_size_mib":256}
}
EOF
echo "=== boot microVM (unchanged agent -> real proxy over vsock) ==="
OUT="$(timeout 90 "$FC" --no-api --config-file "$W/vm.json" 2>&1 || true)"
kill "$MUX" 2>/dev/null || true
echo "----- agent probe -----"; echo "$OUT" | grep -aE "FC-PROXY-(BEGIN|END)|PROBE (PROXY-OK|PROXY-DENY)" || true; echo "-----------------------"

echo "$OUT" | grep -q "PROBE PROXY-OK: PASS" && ok "allowlisted dest reachable via the REAL proxy over vsock (PROXY-OK)" || bad "PROXY-OK failed through the real proxy"
echo "$OUT" | grep -q "PROBE PROXY-DENY: PASS" && ok "non-allowlisted dest REFUSED by the real proxy's allowlist over vsock (PROXY-DENY)" || bad "PROXY-DENY failed (allowlist not enforced over vsock)"

# The decisions must be SIGNED into the chain, and the chain must verify.
sleep 0.3; kill "$PROXY" "$UPSTREAM" 2>/dev/null || true; sleep 0.5
REC_AFTER=$(reccount "$ADIR/provenance.jsonl")
[ "$REC_AFTER" -gt "$REC_BEFORE" ] && ok "the proxy SIGNED the over-vsock decisions into its chain ($REC_BEFORE -> $REC_AFTER)" || bad "no new signed records ($REC_BEFORE -> $REC_AFTER)"
VA="$(CREDENTIALS_DIRECTORY="$SEEDDIR" BULKHEAD_AUDIT_DOMAIN=egress-proxy "$W/bulkhead-collector" verify-audit "$ADIR/provenance.jsonl" 2>&1 || true)"
echo "$VA" | grep -q "verify-audit: OK" && echo "$VA" | grep -q "domain: egress-proxy" && ok "verify-audit OK on the egress chain — over-vsock decisions are the same verifiable records (domain=egress-proxy)" || bad "verify-audit did not pass: $VA"

echo
echo "=== Firecracker mediated-legs SLICE 3: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && { echo "FC PROXY GO"; exit 0; } || { echo "FC PROXY INCOMPLETE"; exit 1; }
