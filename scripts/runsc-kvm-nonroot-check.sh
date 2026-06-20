#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# runsc DEFAULT-tier NON-ROOT in-sandbox hardening proof on REAL /dev/kvm (PRODUCTION-READINESS [81]).
# The production runsc launcher (bulkhead-agent-runsc-launch) historically ran the agent as in-sandbox uid 0:
# the Sentry still contains it (in-sandbox root != host root), but in-sandbox setuid/capset SUCCEED, so a
# compromised agent runs with full in-guest privilege. Tightening the OCI user to a NON-ROOT uid closes that —
# AT the cost of the agent's two functional dependencies (its mediated UNIX legs and its task credential), which
# a non-root uid could lose. This harness proves, under `runsc --platform=kvm` (the production KVM platform) with
# a non-root OCI user, that BOTH the hardening AND function hold together:
#
#   FUNCTION (probe-egress, the cooperative self-test):
#     PROXY-OK — the NON-ROOT agent still reaches its mediated egress leg. The leg is mode 0666 here exactly as
#                the real proxy (src/proxy/main.go) and router (src/router/main.go) chmod theirs, because the
#                agent is a DynamicUser distinct from the proxy's — so cross-uid connect is by design.
#     CRED     — the NON-ROOT agent still READS its broker-delegated task credential (ADR-0015), bound read-only.
#
#   HARDENING (probe-escape, substrate tier, the hostile payload):
#     SETUID/CAPSET CONTAINED — with a non-root in-sandbox uid even the in-sandbox-privilege vectors are DENIED
#                (they were SANDBOX-PRIV under in-sandbox root); RESULT CONTAINED, no host-crossing BREACH.
#
# Needs runsc + real /dev/kvm. Exits 2 INCONCLUSIVE without them. The in-sandbox uid is parameterized (default
# 65534/nobody) via NONROOT_UID/NONROOT_GID to match whatever the launcher pins.
set -eu

REPO="$(cd "$(dirname "$0")/.." && pwd)"
W="${RUNSC_NONROOT_WORK:-/tmp/runsc-nonroot}"
RUNSC="${RUNSC:-runsc}"
UID_NR="${NONROOT_UID:-65534}"
GID_NR="${NONROOT_GID:-65534}"
PASS=0; FAIL=0
ok()  { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

[ -e /dev/kvm ] && ok "/dev/kvm present (real hardware virtualization)" || { echo "RUNSC NONROOT INCONCLUSIVE (no /dev/kvm)"; exit 2; }
command -v "$RUNSC" >/dev/null 2>&1 || { echo "RUNSC NONROOT INCONCLUSIVE (no runsc)"; exit 2; }
command -v go >/dev/null 2>&1 || { echo "RUNSC NONROOT INCONCLUSIVE (no go toolchain)"; exit 2; }

rm -rf "$W"; mkdir -p "$W/bundle/rootfs/usr/bin" "$W/bundle/rootfs/proc" "$W/bundle/rootfs/dev" \
	"$W/bundle/rootfs/sys" "$W/bundle/rootfs/run/bulkhead-egress" "$W/bundle/rootfs/run/creds" \
	"$W/legs" "$W/creds"
( cd "$REPO/src/agent" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$W/bulkhead-agent" . ) || { bad "agent build"; echo "RUNSC NONROOT INCOMPLETE"; exit 1; }
ok "built the static agent"
: > "$W/bundle/rootfs/usr/bin/bulkhead-agent"   # bind-mount target

# A faithful minimal egress-proxy LEG: one CONNECT line in, "OK\n" iff the allowlisted target, else "ERR denied".
# Mode 0666 — exactly how the real proxy/router chmod their UDS for the distinct-DynamicUser agent.
cat > "$W/leg.go" <<'GEOF'
package main

import (
	"bufio"
	"net"
	"os"
	"strings"
)

func main() {
	sock, allow := os.Args[1], os.Args[2]
	_ = os.Remove(sock)
	l, err := net.Listen("unix", sock)
	if err != nil {
		panic(err)
	}
	_ = os.Chmod(sock, 0o666) // cross-uid connect by design (agent is a distinct DynamicUser)
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			line, _ := bufio.NewReader(c).ReadString('\n')
			if strings.TrimSpace(line) == "CONNECT "+allow {
				_, _ = c.Write([]byte("OK\n"))
			} else {
				_, _ = c.Write([]byte("ERR denied\n"))
			}
		}(c)
	}
}
GEOF
( cd "$W" && CGO_ENABLED=0 go build -o "$W/leg" leg.go ) || { bad "leg stub build"; echo "RUNSC NONROOT INCOMPLETE"; exit 1; }

TARGET="127.0.0.1:8088"
"$W/leg" "$W/legs/egress.sock" "$TARGET" & LEG=$!
i=0; while [ $i -lt 50 ] && [ ! -S "$W/legs/egress.sock" ]; do sleep 0.1; i=$((i + 1)); done
LEGMODE="$(stat -c %a "$W/legs/egress.sock" 2>/dev/null || echo '?')"
[ "$LEGMODE" = 666 ] && ok "mediated leg is mode 0666 (as the real proxy/router chmod theirs)" || bad "leg mode is $LEGMODE not 666"
: > "$W/bundle/rootfs/run/bulkhead-egress/egress.sock"   # bind target

# The broker-delegated task credential, read-only, world-readable so any in-sandbox uid reads it
# (the cred dir is the host-isolation boundary; 0444 within it is the launcher's posture for a non-root agent).
printf '%s' "probe the world, report back" > "$W/creds/agent-task"; chmod 0444 "$W/creds/agent-task"
chmod 0711 "$W/creds"   # o+x so the non-root in-sandbox uid (!= gofer owner) TRAVERSES; not listable (no o+r)
: > "$W/bundle/rootfs/run/creds/agent-task"   # bind target

# host-only secret OUTSIDE the bundle (world-readable: only fs ISOLATION can hide it from the sandbox).
SECRET="$W/.host-only-secret"; echo "TOP-SECRET-HOST-ONLY" > "$SECRET"; chmod 644 "$SECRET"

# Shared mount set: the agent binary, the egress leg dir, and the creds dir — all bind-mounted READ-ONLY.
MOUNTS='{"destination":"/proc","type":"proc","source":"proc"},
{"destination":"/dev","type":"tmpfs","source":"tmpfs","options":["nosuid","noexec","nodev"]},
{"destination":"/sys","type":"sysfs","source":"sysfs","options":["nosuid","noexec","nodev","ro"]},
{"destination":"/usr/bin/bulkhead-agent","type":"bind","source":"'"$W"'/bulkhead-agent","options":["bind","ro"]},
{"destination":"/run/bulkhead-egress","type":"bind","source":"'"$W"'/legs","options":["bind","ro"]},
{"destination":"/run/creds","type":"bind","source":"'"$W"'/creds","options":["bind","ro"]}'
NS='{"type":"pid"},{"type":"network"},{"type":"ipc"},{"type":"uts"},{"type":"mount"}'
HEAD='"cwd":"/","capabilities":{"bounding":[],"effective":[],"inheritable":[],"permitted":[]},
"rlimits":[{"type":"RLIMIT_NOFILE","hard":1024,"soft":1024}],"noNewPrivileges":true},
"root":{"path":"rootfs","readonly":true},"hostname":"runsc"'

run() { # <id> <config.json>
	cp "$2" "$W/bundle/config.json"
	"$RUNSC" --rootless --ignore-cgroups delete -force "$1" 2>/dev/null || true
	OUT="$(timeout 90 "$RUNSC" --host-uds=open --rootless --ignore-cgroups --platform=kvm --network=none run -bundle "$W/bundle" "$1" 2>&1 || true)"
	"$RUNSC" --rootless --ignore-cgroups delete -force "$1" 2>/dev/null || true
	echo "$OUT"
}

# ---- FUNCTION: probe-egress as the NON-ROOT in-sandbox uid (leg-reach + cred-read) -------------------------
cat > "$W/cfg-egress.json" <<EOF
{"ociVersion":"1.0.0","process":{"user":{"uid":$UID_NR,"gid":$GID_NR},"args":["/usr/bin/bulkhead-agent","probe-egress"],
"env":["PATH=/usr/bin:/bin","BULKHEAD_EGRESS_SOCK=/run/bulkhead-egress/egress.sock","BULKHEAD_PROBE_PUBLIC=1.1.1.1:443",
"BULKHEAD_PROBE_TARGET=$TARGET","BULKHEAD_PROBE_DENIED=10.255.255.1:80","BULKHEAD_AGENT_TASK_CRED=agent-task","CREDENTIALS_DIRECTORY=/run/creds"],
$HEAD,"mounts":[$MOUNTS],"linux":{"namespaces":[$NS]}}
EOF
echo "=== probe-egress as NON-ROOT in-sandbox uid $UID_NR under runsc --platform=kvm (real KVM) ==="
EG="$(run nr-egress "$W/cfg-egress.json")"
echo "$EG" | grep -aE 'PROBE ' || true
echo "------------------------------------------------------------"
echo "$EG" | grep -qE 'PROBE NOROUTE: PASS'  && ok "non-root: NOROUTE (no route in the netns)"            || bad "non-root: NOROUTE failed"
echo "$EG" | grep -qE 'PROBE ISOLATED: PASS' && ok "non-root: ISOLATED (host loopback not shared)"        || bad "non-root: ISOLATED failed"
echo "$EG" | grep -qE 'PROBE PROXY-OK: PASS' && ok "non-root agent REACHES its mediated egress leg (0666)" || bad "non-root agent CANNOT reach the egress leg"
echo "$EG" | grep -qE 'PROBE CRED: PASS'     && ok "non-root agent READS its task credential (bound ro)"   || bad "non-root agent CANNOT read its task credential"

# ---- HARDENING: probe-escape (substrate) as the NON-ROOT uid (in-sandbox priv now DENIED) -----------------
cat > "$W/cfg-escape.json" <<EOF
{"ociVersion":"1.0.0","process":{"user":{"uid":$UID_NR,"gid":$GID_NR},"args":["/usr/bin/bulkhead-agent","probe-escape"],
"env":["PATH=/usr/bin:/bin","BULKHEAD_PROBE_TIER=substrate","BULKHEAD_PROBE_HOST_SECRET=$SECRET","BULKHEAD_PROBE_PUBLIC=1.1.1.1:443"],
$HEAD,"mounts":[$MOUNTS],"linux":{"namespaces":[$NS]}}
EOF
echo
echo "=== probe-escape (substrate) as NON-ROOT in-sandbox uid $UID_NR under runsc --platform=kvm (real KVM) ==="
ES="$(run nr-escape "$W/cfg-escape.json")"
echo "$ES" | grep -aE 'ESCAPE ' || true
echo "------------------------------------------------------------"
# The whole point of [81]: with a non-root uid even the in-sandbox-priv vectors are DENIED (CONTAINED),
# not SANDBOX-PRIV. setuid(0) and capset must now fail.
echo "$ES" | grep -qE 'ESCAPE SETUID: CONTAINED' && ok "non-root: setuid(0) CONTAINED (was SANDBOX-PRIV under in-sandbox root)" || bad "non-root: setuid not contained"
echo "$ES" | grep -qE 'ESCAPE CAPSET: CONTAINED' && ok "non-root: capset CONTAINED"                                          || bad "non-root: capset not contained"
for v in IO_URING DIRECT_EGRESS CONTROL_SOCK HOST_SECRET; do
	echo "$ES" | grep -qE "ESCAPE $v: CONTAINED" && ok "non-root: $v CONTAINED" || bad "non-root: $v NOT contained"
done
echo "$ES" | grep -qE 'ESCAPE RESULT: CONTAINED' && ok "non-root: RESULT CONTAINED (every vector denied)" || bad "non-root: RESULT not CONTAINED"
echo "$ES" | grep -q 'ESCAPE RESULT: BREACH' && bad "non-root: a host-meaningful vector BREACHED" || ok "non-root: no BREACH"

kill "$LEG" 2>/dev/null || true
echo
echo "=== runsc NON-ROOT in-sandbox hardening (real KVM, --platform=kvm): $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && { echo "RUNSC NONROOT GO"; exit 0; } || { echo "RUNSC NONROOT INCOMPLETE"; exit 1; }
