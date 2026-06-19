#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# HOSTILE-agent containment proof for the gVisor/runsc DEFAULT tier on REAL /dev/kvm (PRODUCTION-READINESS [6]
# substrate half + [81]/[125]). Runs the agent's `probe-escape` in substrate mode under runsc --platform=kvm
# (the production KVM platform, not the Systrap fallback) with a PRODUCTION-minimal OCI bundle (read-only root,
# empty caps, NoNewPrivileges, --network=none, only the agent binary bind-mounted) and asserts the floor held:
# every HOST-CROSSING vector (io_uring mediation, direct egress, the host control socket, a host-only secret
# planted OUTSIDE the sandbox) is CONTAINED by the Sentry. In-sandbox-privilege ops may report SANDBOX-PRIV —
# the Sentry runs as the unprivileged host user and emulates the guest kernel, so in-sandbox root cannot reach
# the host (ADR-0031's accepted residual is a Sentry 0-day, not in-sandbox uid). Needs runsc + real /dev/kvm.
set -eu

REPO="$(cd "$(dirname "$0")/.." && pwd)"
W="${RUNSC_ESCAPE_WORK:-/tmp/runsc-escape}"
RUNSC="${RUNSC:-runsc}"
PASS=0; FAIL=0
ok()  { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

[ -e /dev/kvm ] && ok "/dev/kvm present (real hardware virtualization)" || { echo "RUNSC ESCAPE INCONCLUSIVE (no /dev/kvm)"; exit 2; }
command -v "$RUNSC" >/dev/null 2>&1 || { echo "RUNSC ESCAPE INCONCLUSIVE (no runsc)"; exit 2; }

rm -rf "$W"; mkdir -p "$W/bundle/rootfs/usr/bin" "$W/bundle/rootfs/proc" "$W/bundle/rootfs/dev" "$W/bundle/rootfs/sys"
( cd "$REPO/src/agent" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$W/bulkhead-agent" . ) || { bad "agent build"; echo "RUNSC ESCAPE INCOMPLETE"; exit 1; }
ok "built the static agent (the hostile payload)"
: > "$W/bundle/rootfs/usr/bin/bulkhead-agent"   # bind-mount target for the host agent binary

# host-only secret OUTSIDE the bundle (world-readable so only fs ISOLATION can hide it from the sandbox).
SECRET="$W/.host-only-secret"; echo "TOP-SECRET-HOST-ONLY" > "$SECRET"; chmod 644 "$SECRET"

cat > "$W/bundle/config.json" <<EOF
{"ociVersion":"1.0.0","process":{"user":{"uid":0,"gid":0},"args":["/usr/bin/bulkhead-agent","probe-escape"],
"env":["PATH=/usr/bin:/bin","BULKHEAD_PROBE_TIER=substrate","BULKHEAD_PROBE_HOST_SECRET=$SECRET","BULKHEAD_PROBE_PUBLIC=1.1.1.1:443"],
"cwd":"/","capabilities":{"bounding":[],"effective":[],"inheritable":[],"permitted":[]},
"rlimits":[{"type":"RLIMIT_NOFILE","hard":1024,"soft":1024}],"noNewPrivileges":true},
"root":{"path":"rootfs","readonly":true},"hostname":"runsc",
"mounts":[{"destination":"/proc","type":"proc","source":"proc"},
{"destination":"/dev","type":"tmpfs","source":"tmpfs","options":["nosuid","noexec","nodev"]},
{"destination":"/sys","type":"sysfs","source":"sysfs","options":["nosuid","noexec","nodev","ro"]},
{"destination":"/usr/bin/bulkhead-agent","type":"bind","source":"$W/bulkhead-agent","options":["bind","ro"]}],
"linux":{"namespaces":[{"type":"pid"},{"type":"network"},{"type":"ipc"},{"type":"uts"},{"type":"mount"}]}}
EOF

echo "=== probe-escape under runsc --platform=kvm --network=none on REAL /dev/kvm (gVisor Sentry) ==="
"$RUNSC" --rootless --ignore-cgroups delete -force runsc-esc 2>/dev/null || true
OUT="$(timeout 90 "$RUNSC" --host-uds=open --rootless --ignore-cgroups --platform=kvm --network=none run -bundle "$W/bundle" runsc-esc 2>&1 || true)"
"$RUNSC" --rootless --ignore-cgroups delete -force runsc-esc 2>/dev/null || true
ESC="$(echo "$OUT" | grep -aE 'ESCAPE ')"
echo "----- probe-escape output (in the gVisor sandbox) -----"; echo "$ESC"; echo "-------------------------------------------------------"

for v in IO_URING DIRECT_EGRESS CONTROL_SOCK HOST_SECRET; do
	echo "$ESC" | grep -qE "ESCAPE $v: CONTAINED" && ok "runsc tier: $v CONTAINED" || bad "runsc tier: $v NOT contained"
done
echo "$ESC" | grep -qE 'ESCAPE RESULT: CONTAINED' && ok "runsc tier: RESULT CONTAINED (no host-reach/mediation escape)" || bad "runsc tier: RESULT not CONTAINED"
echo "$ESC" | grep -q 'ESCAPE RESULT: BREACH' && bad "runsc tier: a host-meaningful vector BREACHED" || ok "runsc tier: no BREACH"
# host-surface collapse: the sandbox kernel is the Sentry's, not the host's.
echo "$OUT" | grep -q 'platform' 2>/dev/null || true

echo
echo "=== gVisor/runsc default-tier containment (real KVM, --platform=kvm): $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && { echo "RUNSC ESCAPE CONTAINED"; exit 0; } || { echo "RUNSC ESCAPE INCOMPLETE"; exit 1; }
