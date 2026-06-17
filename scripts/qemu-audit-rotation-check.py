#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Yocto LIVE check for ADR-0040 bounded-retention audit-chain segment rotation (security-review R9).

The unbounded-/data DoS fix: a chain seals its live file into numbered segments (<live>.NNNNNN) at a
byte threshold, keeps the newest BULKHEAD_AUDIT_SEGMENTS_KEEP, and prunes the rest, so one noisy tier
cannot fill the fixed 100 MB /data and starve every chain into a fail-closed append DoS. The unit tests
prove the mechanics; this proves the two things only a real boot can: (1) a REAL box whose egress chain
has rotated AND head-pruned (oldest segment > 1, so the verifier's retained-head anchor is load-bearing)
verifies OK through the actual `bulkhead-collector verify-audit` boot gate, and (2) that chain survives
a real reboot — the boot gate stays green (no false-brick), the proxy reseeds across boots, the prior
boot's sealed segment is re-permissioned group-readable (the DynamicUser cross-boot fix), and appends
continue link-continuous across the seam.

Production ships 8 MiB segments (impractical to fill in a test), so BOOT 1 drops in a TINY threshold
(BULKHEAD_AUDIT_SEGMENT_BYTES) and drives the confined egress probe several times — spaced out (and
reset-failed) so systemd's start-rate-limit doesn't swallow the runs — to force several rotations + a
prune. The drop-in lives in /run (tmpfs), so BOOT 2 runs at the production threshold over the segments
BOOT 1 left — exactly the field shape (a box that rotated, then rebooted).

Driven through yocto/scripts/run-qemu-tpm.sh (OVMF + swtpm + the wic) in `snapshot` mode, one qemu
process spanning two boots (in-guest `systemctl reboot`, so /data persists across the reboot). Stdlib
only; serial-console driven. Mirrors qemu-egress-reboot-check.py's harness.
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
TIMEOUT = int(os.environ.get("BULKHEAD_VERIFY_TIMEOUT", "900"))

WAIT_PROXY = ("for i in $(seq 1 90); do systemctl is-active --quiet "
              "bulkhead-egress-proxy && break; sleep 2; done")

# Drive the confined egress probe N times, SPACED (sleep) and reset-failed before each, so systemd's
# default start-rate-limit (5 starts / 10 s) does not silently swallow the later runs — the failure
# mode that left only one effective run (2 records, one rotation, no prune) the first time around. Each
# run signs an allow + a deny egress record; >=2 effective runs => >=3 records => at keep=1 the head
# prunes (oldest retained segment number > 1), which is what makes the verifier's retained-head anchor
# load-bearing on a real box.
DRIVE_EGRESS = ("for n in 1 2 3 4 5; do "
                "systemctl reset-failed bulkhead-agent-confined@egressprobe.service 2>/dev/null; "
                "systemctl restart bulkhead-agent-confined@egressprobe.service; sleep 6; done")

# Per-boot allowlist + probe drop-ins (recreated each boot: /run is a tmpfs wiped by the reboot).
ALLOW_AND_PROBE = [
    "printf '127.0.0.1\\n' > /run/egress-allow-test.conf",
    "mkdir -p /run/systemd/system/bulkhead-egress-proxy.service.d",
    ("printf '[Service]\\nEnvironment=BULKHEAD_EGRESS_ALLOWLIST=/run/egress-allow-test.conf\\n"
     "Environment=BULKHEAD_EGRESS_ALLOW_INTERNAL_CIDRS=127.0.0.0/8\\n'"
     " > /run/systemd/system/bulkhead-egress-proxy.service.d/10-test.conf"),
    "mkdir -p /run/systemd/system/bulkhead-agent-confined@egressprobe.service.d",
    ("printf '[Service]\\nType=oneshot\\nEnvironment=BULKHEAD_PROBE_TARGET=127.0.0.1:8088\\n"
     "Environment=BULKHEAD_PROBE_DENIED=10.255.255.1:80\\n"
     "Environment=BULKHEAD_PROBE_PUBLIC=1.1.1.1:443\\n'"
     " > /run/systemd/system/bulkhead-agent-confined@egressprobe.service.d/10-test.conf"),
]

# BOOT1 SETUP: a TINY rotation threshold (zz- sorts after the baked *-data.conf drop-in, so its
# BULKHEAD_AUDIT_SEGMENT_BYTES wins) so every signed record rotates; keep=1 inherited from the baked
# drop-in => the head prunes (oldest segment > 1).
SETUP_B1 = [
    "EC=/data/bulkhead/audit-egress/provenance.jsonl",
    WAIT_PROXY,
    "systemctl start bulkhead-mockchat.service",
] + ALLOW_AND_PROBE + [
    ("printf '[Service]\\nEnvironment=BULKHEAD_AUDIT_SEGMENT_BYTES=200\\n'"
     " > /run/systemd/system/bulkhead-egress-proxy.service.d/zz-rotate-test.conf"),
    "systemctl daemon-reload",
    "systemctl restart bulkhead-egress-proxy.service",
    "sleep 1",
    DRIVE_EGRESS,
]

PROBE_B1 = SETUP_B1 + [
    "echo '<<<BOOT1'",
    'echo "proxy-active=$(systemctl is-active bulkhead-egress-proxy)"',
    'echo "verifyaudit-active=$(systemctl is-active bulkhead-verify-audit)"',
    'echo "chain-on-data=$([ -f $EC ] && echo yes || echo no)"',
    'echo "records-b1=$(grep -hc . $EC $EC.[0-9]* 2>/dev/null | awk \'{s+=$1} END{print s+0}\')"',
    "echo \"foot-b1=$(stat -c %s $EC $EC.[0-9]* 2>/dev/null | awk '{s+=$1} END{print s+0}')\"",
    # Robust, quote-free segment enumeration parsed in Python (avoids a fragile in-guest sed pipeline).
    "echo SEGLIST1_START",
    "ls $EC.[0-9]* 2>/dev/null",
    "echo SEGLIST1_END",
    "bulkhead-collector verify-audit $EC >/tmp/va 2>&1",
    "echo \"verify-ok-b1=$(grep -c 'verify-audit: OK' /tmp/va)\"",
    "echo \"domain-b1=$(grep -c 'domain: egress-proxy' /tmp/va)\"",
    "TIP1=$(sed -n 's/.*tip=\\([0-9a-f]*\\).*/\\1/p' /tmp/va)",
    'echo "tip-b1=$TIP1"',
    "printf '%s' \"$TIP1\" > /data/rot-tip-b1.txt",
    "echo 'BOOT1END>>>'",
    "systemctl reboot",
]

# BOOT2: the /run drop-ins are gone (tmpfs wiped) => the proxy runs at the PRODUCTION 8 MiB threshold,
# but the rotated+pruned segments BOOT1 left persist on /data. This is the field shape. The boot gate's
# state is read BEFORE we touch anything (it ran at boot over the segmented+pruned chain).
SETUP_B2 = [
    "EC=/data/bulkhead/audit-egress/provenance.jsonl",
    WAIT_PROXY,
    "systemctl start bulkhead-mockchat.service",
] + ALLOW_AND_PROBE + [
    "systemctl daemon-reload",
    "systemctl restart bulkhead-egress-proxy.service",
    "sleep 1",
    "systemctl start bulkhead-agent-confined@egressprobe.service",
]

PROBE_B2 = [
    "EC=/data/bulkhead/audit-egress/provenance.jsonl",
    "echo '<<<BOOT2'",
    'echo "records-before=$(grep -hc . $EC $EC.[0-9]* 2>/dev/null | awk \'{s+=$1} END{print s+0}\')"',
    'echo "nsegs-before=$(ls -1 $EC.[0-9]* 2>/dev/null | wc -l)"',
    'echo "verifyaudit-active=$(systemctl is-active bulkhead-verify-audit)"',
    # The prior-boot sealed segment must have been re-permissioned group-readable by the proxy unit's
    # cross-boot ExecStartPre (the DynamicUser fix), so the next boot's uid could read it if needed.
    "echo PERM2_START",
    "stat -c %a:%G $EC.[0-9]* 2>/dev/null",
    "echo PERM2_END",
] + SETUP_B2 + [
    'echo "proxy-active=$(systemctl is-active bulkhead-egress-proxy)"',
    'echo "records-after=$(grep -hc . $EC $EC.[0-9]* 2>/dev/null | awk \'{s+=$1} END{print s+0}\')"',
    "bulkhead-collector verify-audit $EC >/tmp/va2 2>&1",
    "echo \"verify-ok-b2=$(grep -c 'verify-audit: OK' /tmp/va2)\"",
    "echo \"domain-b2=$(grep -c 'domain: egress-proxy' /tmp/va2)\"",
    "bulkhead-collector verify-audit $EC --since=@/data/rot-tip-b1.txt >/tmp/nr 2>&1",
    "echo \"norewind-b2=$(grep -c 'no-rewind CLEAN' /tmp/nr)\"",
    "echo 'BOOT2END>>>'",
    "poweroff",
]


def main():
    if not os.path.exists(RUNQEMU_TPM):
        print(f"missing {RUNQEMU_TPM}", file=sys.stderr)
        return 2

    tpmstate = os.environ.get("BULKHEAD_TPMSTATE") or tempfile.mkdtemp(prefix="bh-rot-tpm.")
    env = dict(os.environ, BULKHEAD_TPMSTATE=tpmstate)
    proc = subprocess.Popen(
        ["bash", RUNQEMU_TPM, "snapshot"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, bufsize=0, env=env,
    )

    def send(s, chunk=16, delay=0.02):
        data = s.encode()
        try:
            for i in range(0, len(data), chunk):
                proc.stdin.write(data[i:i + chunk])
                proc.stdin.flush()
                time.sleep(delay)
        except (BrokenPipeError, ValueError):
            pass

    def send_probe(lines):
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
            send_probe(PROBE_B1 if boot == 1 else PROBE_B2)
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

    def num(body, key):
        try:
            return int(kv(body, key) or 0)
        except ValueError:
            return 0

    def seg_numbers(body, start, end):
        # Parse the segment numbers from the `ls <chain>.NNNNNN` block between two markers, robust to
        # the serial console (no in-guest sed/sort to corrupt). Returns a sorted list of ints.
        m = re.search(rf"^{start}\n(.*?)\n{end}$", body, re.S | re.M)
        if not m:
            return []
        nums = []
        for ln in m.group(1).splitlines():
            ln = ln.strip()
            if not ln:
                continue
            tail = ln.rsplit(".", 1)[-1]
            if tail.isdigit():
                nums.append(int(tail))
        return sorted(nums)

    def block_line(body, start, end, pat):
        # First line INSIDE the marker block that matches `pat` — skips the shell's command-echo lines
        # (root@...# stat ...) that the serial console interleaves with real output.
        m = re.search(rf"^{start}\n(.*?)\n{end}$", body, re.S | re.M)
        if not m:
            return ""
        for ln in m.group(1).splitlines():
            ln = ln.strip()
            if re.match(pat, ln):
                return ln
        return ""

    segs_b1 = seg_numbers(b1, "SEGLIST1_START", "SEGLIST1_END")
    nseg_b1 = len(segs_b1)
    oldest_b1 = segs_b1[0] if segs_b1 else 0
    foot_b1 = num(b1, "foot-b1")
    rec_before = num(b2, "records-before")
    rec_after = num(b2, "records-after")
    perm_b2 = block_line(b2, "PERM2_START", "PERM2_END", r"\d{3,4}:\S+$")  # e.g. "640:bulkhead-audit"

    checks = [
        ("BOOT1 captured", bool(m1)),
        ("egress proxy active at boot", kv(b1, "proxy-active") == "active"),
        ("verify-audit boot gate active (b1)", kv(b1, "verifyaudit-active") == "active"),
        ("egress chain persisted on /data", kv(b1, "chain-on-data") == "yes"),
        ("rotation produced >=1 sealed segment", nseg_b1 >= 1),
        ("retention held (keep=1 => exactly 1 retained segment)", nseg_b1 == 1),
        ("HEAD was pruned (oldest retained segment number > 1)", oldest_b1 > 1),
        ("footprint BOUNDED (live+segments well under the unbounded case)", 0 < foot_b1 < 5000),
        ("verify-audit OK on the rotated+pruned chain (retained-head anchor live)", kv(b1, "verify-ok-b1") == "1"),
        ("audit domain is egress-proxy (b1)", kv(b1, "domain-b1") == "1"),
        ("chain tip recorded", bool(kv(b1, "tip-b1"))),
        ("BOOT2 captured (in-guest reboot succeeded)", bool(m2)),
        # The headline reboot assertion: the boot gate did NOT brick on the segmented+pruned chain.
        ("verify-audit boot gate ACTIVE after reboot (no false-brick on a pruned chain)",
         kv(b2, "verifyaudit-active") == "active"),
        ("egress proxy ACTIVE after reboot (reseeded across boots, fail-closed)",
         kv(b2, "proxy-active") == "active"),
        ("rotated chain SURVIVED the reboot (segments + records persisted)",
         num(b2, "nsegs-before") >= 1 and rec_before >= 1),
        ("prior-boot segment re-permissioned 0640:bulkhead-audit (DynamicUser cross-boot read)",
         perm_b2.startswith("640:") and "bulkhead-audit" in perm_b2),
        ("verify-audit OK on the /data chain after reboot (b2)", kv(b2, "verify-ok-b2") == "1"),
        ("cross-boot APPEND succeeded across the seam (record count grew)", rec_after > rec_before),
        ("no-rewind CLEAN: b2 tip extends b1 tip (continuity across rotation + reboot)",
         kv(b2, "norewind-b2") == "1"),
    ]

    print("\n\n=== bulkhead Yocto audit-chain rotation (ADR-0040 / R9) verification ===")
    ok = True
    for name, cond in checks:
        print(("PASS" if cond else "FAIL") + ": " + name)
        ok = ok and cond
    print("YOCTO AUDIT ROTATION OK" if ok else "YOCTO AUDIT ROTATION INCOMPLETE")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
