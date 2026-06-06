#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Yocto LIVE check for the router's signed routing-decision chain on /data (ADR-0027
production seam, wired in be53670 + the recipe pins to e3239ef).

Unlike scripts/qemu-router-check.py (the Buildroot prototype, which writes an EPHEMERAL
per-boot key to /var/lib), this boots the production wic image under a software TPM and
proves the PRODUCTION path:

  - the bulkhead-audit system group exists (baked at image build via extrausers),
  - the router persists its chain on the /data partition at /data/bulkhead/audit-router,
    signed with the SHARED TPM-sealed audit-seed (the seal + verify-audit boot gate are
    active => the gate verified the chain against the sealed seed and let boot proceed),
  - the chain dir is the setgid, group-writable 2770 root:bulkhead-audit dir the
    DynamicUser fix installs, and
  - THE LOAD-BEARING CROSS-BOOT CASE: after an in-guest reboot (a fresh systemd state,
    a possibly-different DynamicUser uid), the router reopens the PRIOR boot's chain and
    APPENDS to it (the group fix working), and verify-audit reports no-rewind CLEAN
    tying the second-boot tip back to the first-boot tip.

Driven through run-qemu-tpm.sh so OVMF + swtpm + the wic disk are assembled exactly as
the project boots them. A single qemu process spans both boots (in-guest `systemctl
reboot`), so the /data partition and the sealed TPM seed persist across the reboot. The
deploy artifact is untouched (runqemu's snapshot overlay is discarded on exit). Stdlib
only.

Serial-console driving notes: the guest 16550 UART has a 16-byte RX FIFO and a canonical
input-line cap, so we (a) drip-feed each line in <=FIFO-size chunks, and (b) send the
probe as MANY SHORT standalone lines rather than one long line — a long single line
overflows the cap, truncates mid-quote, and hangs the shell at a PS2 `>`.
"""

import os
import re
import select
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNQEMU_TPM = os.path.join(ROOT, "yocto", "scripts", "run-qemu-tpm.sh")
TIMEOUT = int(os.environ.get("BULKHEAD_YOCTO_CHECK_TIMEOUT", "900"))

# Router health gate (router comes up during boot); short prompt -> local tier, a long
# prompt -> api tier. The routing DECISION (and its signed record) is written BEFORE the
# upstream is dialed (ADR-0027), so even with llama down (no model disk in this harness)
# and no api key (503), each request still appends one signed record — what we verify.
HEALTH = ("for i in $(seq 1 90); do curl -sf -m5 http://127.0.0.1:8080/health "
          ">/dev/null 2>&1 && break; sleep 2; done")
ROUTE_LOCAL = ("curl -s -m120 -o /dev/null -w 'local route=%header{x-bulkhead-route} "
               "status=%{http_code}\\n' http://127.0.0.1:8080/v1/chat/completions "
               "-H 'content-type: application/json' "
               "-d '{\"messages\":[{\"role\":\"user\",\"content\":\"pong?\"}],\"max_tokens\":8}'")
ROUTE_LONG = "LONG=$(yes x | head -n 2300 | tr -d '\\n')"
ROUTE_API = ("curl -s -m30 -o /dev/null -w 'api route=%header{x-bulkhead-route} "
             "status=%{http_code}\\n' http://127.0.0.1:8080/v1/chat/completions "
             "-H 'content-type: application/json' "
             "-d \"{\\\"messages\\\":[{\\\"role\\\":\\\"user\\\",\\\"content\\\":\\\"$LONG\\\"}],\\\"max_tokens\\\":8}\"")

# Each entry is ONE short shell line (executed in the same interactive shell, so vars
# persist). $RC abbreviates the chain path to keep the stat/grep lines short.
PROBE_BOOT1 = [
    "RC=/data/bulkhead/audit-router/provenance.jsonl",
    HEALTH,
    "echo '<<<BOOT1'",
    'echo "router-active=$(systemctl is-active bulkhead-router)"',
    'echo "seal-active=$(systemctl is-active bulkhead-seal-audit-key)"',
    'echo "verifyaudit-active=$(systemctl is-active bulkhead-verify-audit)"',
    'echo "selftest-active=$(systemctl is-active bulkhead-selftest)"',
    "echo \"group-present=$(grep -c '^bulkhead-audit:' /etc/group)\"",
    ROUTE_LOCAL,
    ROUTE_LONG,
    ROUTE_API,
    'echo "chain-on-data=$([ -f $RC ] && echo yes || echo no)"',
    'echo "records-b1=$(grep -c . $RC 2>/dev/null || echo 0)"',
    "echo \"dir-perms=$(stat -c '%a %U:%G' /data/bulkhead/audit-router 2>/dev/null)\"",
    "echo \"file-perms-b1=$(stat -c '%a %U:%G' $RC 2>/dev/null)\"",
    "echo \"file-uid-b1=$(stat -c '%u' $RC 2>/dev/null)\"",
    "bulkhead-collector verify-audit $RC >/tmp/va 2>&1",
    "echo \"verify-ok-b1=$(grep -c 'verify-audit: OK' /tmp/va)\"",
    "TIP1=$(sed -n 's/.*tip=\\([0-9a-f]*\\).*/\\1/p' /tmp/va)",
    'echo "tip-b1=$TIP1"',
    "printf '%s' \"$TIP1\" > /data/router-tip-b1.txt",
    "echo 'BOOT1END>>>'",
    "systemctl reboot",
]

PROBE_BOOT2 = [
    "RC=/data/bulkhead/audit-router/provenance.jsonl",
    HEALTH,
    "echo '<<<BOOT2'",
    'echo "router-active=$(systemctl is-active bulkhead-router)"',
    'echo "verifyaudit-active=$(systemctl is-active bulkhead-verify-audit)"',
    'echo "records-before=$(grep -c . $RC 2>/dev/null || echo 0)"',
    "echo \"file-uid-persisted=$(stat -c '%u' $RC 2>/dev/null)\"",
    "echo \"file-perms-b2=$(stat -c '%a %U:%G' $RC 2>/dev/null)\"",
    "RPID=$(systemctl show -p MainPID --value bulkhead-router 2>/dev/null)",
    "echo \"router-proc-uid-b2=$(grep -m1 '^Uid:' /proc/$RPID/status 2>/dev/null | tr -s '\\t ' ' ' | cut -d' ' -f2)\"",
    ROUTE_LOCAL,
    ROUTE_LONG,
    ROUTE_API,
    'echo "records-after=$(grep -c . $RC 2>/dev/null || echo 0)"',
    "bulkhead-collector verify-audit $RC >/tmp/va2 2>&1",
    "echo \"verify-ok-b2=$(grep -c 'verify-audit: OK' /tmp/va2)\"",
    "bulkhead-collector verify-audit $RC --since=@/data/router-tip-b1.txt >/tmp/nr 2>&1",
    "echo \"norewind-b2=$(grep -c 'no-rewind CLEAN' /tmp/nr)\"",
    "echo 'BOOT2END>>>'",
    "poweroff",
]


def main():
    if not os.path.exists(RUNQEMU_TPM):
        print(f"missing {RUNQEMU_TPM}", file=sys.stderr)
        return 2

    tpmstate = os.environ.get("BULKHEAD_TPMSTATE") or tempfile.mkdtemp(prefix="bh-yocto-tpm.")
    env = dict(os.environ, BULKHEAD_TPMSTATE=tpmstate)

    # `snapshot`: runqemu attaches the wic read-only with writes to a temp overlay, so
    # this run starts from the image's pristine (empty) /data and the deploy artifact is
    # never mutated — runs are repeatable and don't pollute each other's audit chains.
    # The overlay lives for the qemu PROCESS lifetime, so the in-guest reboot below still
    # sees boot 1's /data writes; the overlay is discarded only when qemu exits.
    proc = subprocess.Popen(
        ["bash", RUNQEMU_TPM, "snapshot"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, bufsize=0, env=env,
    )

    def send(s, chunk=16, delay=0.02):
        # Drip-feed: a bulk write overflows the guest 16550 UART RX FIFO (16 bytes, no
        # flow control) and drops characters. Send in <=FIFO-size chunks with a small gap.
        data = s.encode()
        try:
            for i in range(0, len(data), chunk):
                proc.stdin.write(data[i:i + chunk])
                proc.stdin.flush()
                time.sleep(delay)
        except (BrokenPipeError, ValueError):
            pass

    def send_probe(lines):
        # One short line at a time, each newline-terminated; a 0.5s gap lets the shell
        # consume each line (the rest type-ahead-buffer behind the brief HEALTH wait).
        for ln in lines:
            send(ln + "\n")
            time.sleep(0.5)

    out = []
    boot = 1
    logged_in = probed = False
    t_login = 0.0
    deadline = time.time() + TIMEOUT
    while time.time() < deadline and proc.poll() is None:
        r, _, _ = select.select([proc.stdout], [], [], 1.0)
        if r:
            chunk = os.read(proc.stdout.fileno(), 4096)
            if not chunk:
                break
            out.append(chunk.decode(errors="replace"))
            sys.stdout.write(chunk.decode(errors="replace"))
            sys.stdout.flush()
        full = "".join(out).replace("\r", "")
        tail = full[-400:]
        if not logged_in and re.search(r"login:\s*$", tail):
            send("root\n")
            logged_in = True
            t_login = time.time()
            continue
        if logged_in and tail.endswith("Password: "):
            send("\n")
        if logged_in and not probed and time.time() - t_login > 3:
            send_probe(PROBE_BOOT1 if boot == 1 else PROBE_BOOT2)
            probed = True
            continue
        if boot == 1 and re.search(r"\n<<<BOOT1\n.*?\nBOOT1END>>>", full, re.S):
            boot = 2
            logged_in = probed = False
            continue
        if re.search(r"\n<<<BOOT2\n.*?\nBOOT2END>>>", full, re.S):
            break

    try:
        proc.wait(timeout=25)
    except subprocess.TimeoutExpired:
        proc.kill()

    text = "".join(out).replace("\r", "")
    m1 = re.search(r"\n<<<BOOT1\n(.*?)\nBOOT1END>>>", text, re.S)
    m2 = re.search(r"\n<<<BOOT2\n(.*?)\nBOOT2END>>>", text, re.S)
    b1 = m1.group(1) if m1 else ""
    b2 = m2.group(1) if m2 else ""

    def kv(body, key):
        m = re.search(rf"^{re.escape(key)}=(.*)$", body, re.M)
        return m.group(1).strip() if m else None

    rec_b1 = int(kv(b1, "records-b1") or 0)
    rec_before = int(kv(b2, "records-before") or 0)
    rec_after = int(kv(b2, "records-after") or 0)
    uid_b1 = kv(b1, "file-uid-b1")
    uid_b2_proc = kv(b2, "router-proc-uid-b2")
    dir_perms = kv(b1, "dir-perms") or ""
    fperms_b2 = kv(b2, "file-perms-b2") or ""

    checks = [
        ("BOOT1 captured", bool(m1)),
        ("bulkhead-audit group exists (extrausers)", kv(b1, "group-present") == "1"),
        ("router active", kv(b1, "router-active") == "active"),
        ("seal-audit-key active (seed provisioned)", kv(b1, "seal-active") == "active"),
        ("verify-audit boot gate active (sealed-seed verify passed)", kv(b1, "verifyaudit-active") == "active"),
        ("selftest gate active", kv(b1, "selftest-active") == "active"),
        ("chain persisted on /data", kv(b1, "chain-on-data") == "yes"),
        ("router wrote >=1 signed record", rec_b1 >= 1),
        ("chain dir is 2770 root:bulkhead-audit", dir_perms.startswith("2770 root:bulkhead-audit")),
        ("verify-audit OK on the /data chain (b1)", kv(b1, "verify-ok-b1") == "1"),
        ("tip recorded", bool(kv(b1, "tip-b1"))),
        ("BOOT2 captured (in-guest reboot succeeded)", bool(m2)),
        ("router active after reboot", kv(b2, "router-active") == "active"),
        ("verify-audit boot gate active after reboot", kv(b2, "verifyaudit-active") == "active"),
        ("chain SURVIVED the reboot (records persisted)", rec_before >= rec_b1 and rec_before >= 1),
        ("prior chain file is group-writable 0660 bulkhead-audit", fperms_b2.startswith("660 ") and "bulkhead-audit" in fperms_b2),
        ("cross-boot APPEND succeeded (record count grew)", rec_after > rec_before),
        ("verify-audit OK on the /data chain (b2)", kv(b2, "verify-ok-b2") == "1"),
        ("no-rewind CLEAN: b2 tip extends b1 tip", kv(b2, "norewind-b2") == "1"),
    ]

    print("\n\n=== bulkhead Yocto router /data chain verification ===")
    ok = True
    for name, cond in checks:
        print(("PASS" if cond else "FAIL") + ": " + name)
        ok = ok and cond
    note = "same-or-unknown"
    if uid_b1 and uid_b2_proc and uid_b1 != uid_b2_proc:
        note = f"DIFFERENT uid (b1 wrote as {uid_b1}, b2 router is {uid_b2_proc}) — group fix directly exercised"
    elif uid_b1 and uid_b2_proc:
        note = f"same uid ({uid_b1}) this run — append still proven via group-writable perms"
    print(f"INFO: cross-boot writer = {note}")
    print("YOCTO ROUTER /data OK" if ok else "YOCTO ROUTER /data INCOMPLETE")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
