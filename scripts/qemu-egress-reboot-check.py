#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Yocto LIVE check that the EGRESS PROXY's signed egress-decision chain survives a reboot
AND that the proxy comes back up fail-closed under its OWN sealed seed (ADR-0034/0017/0008).

This is the egress sibling of scripts/qemu-yocto-router-check.py. The router test proves the
/data + sealed-seed machinery for the ROUTER's chain; the egress proxy reuses the byte-identical
pattern (bulkhead-egress-proxy-data.conf mirrors bulkhead-router-data.conf), but it is a DISTINCT
unit, a DISTINCT chain dir (/data/bulkhead/audit-egress), a DISTINCT audit domain (egress-proxy),
and — load-bearing — its OWN LoadCredential=audit-seed unseal under BULKHEAD_REQUIRE_SEALED_KEY=1.
The router reboot test exercises the router's seed, not the proxy's. So a latent egress-specific
persistence or sealed-seed brick would pass verify-yocto-router and only surface here.

What it proves, across one qemu process spanning two boots (in-guest `systemctl reboot`, so /data
and the sealed TPM seed persist):

  BOOT 1 — the egress proxy is up under the sealed seed (the verify-audit boot gate is active =>
    it verified every signed chain, incl. egress, against the sealed seed and let boot proceed).
    A confined agent (bulkhead-agent-confined@, no-route netns) runs the egress probe, which makes
    the proxy ALLOW one destination and DENY another; the proxy signs both into its hash-chained
    egress log on /data. We capture the record count + the chain tip, and verify-audit reports OK
    with domain=egress-proxy. The probe's io_uring_setup check (ADR-0033) is asserted too.

  BOOT 2 — after the reboot, the proxy is ACTIVE AGAIN. Because it runs REQUIRE_SEALED_KEY=1, an
    active proxy proves the sealed seed persisted on /data and unsealed (a missing/garbled seed
    fails the unit CLOSED). The prior boot's chain is still there (records survived); a fresh probe
    APPENDS more signed records (the DynamicUser group-write fix working cross-boot); verify-audit
    is OK; and a no-rewind check ties boot 2's tip back to boot 1's tip.

Driven through yocto/scripts/run-qemu-tpm.sh (OVMF + swtpm + the wic), `snapshot` so the deploy
artifact is untouched and runs don't pollute each other. Stdlib only. Serial-console driving
mirrors the router test (16550 RX FIFO: drip-feed each line in <=FIFO chunks; keep lines short).
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

# Wait for the egress proxy to be up (it starts during boot, after the seal service).
WAIT_PROXY = ("for i in $(seq 1 90); do systemctl is-active --quiet "
              "bulkhead-egress-proxy && break; sleep 2; done")

# Per-boot SETUP: /run is a tmpfs wiped by the reboot, so BOTH boots must (re)create the test
# allowlist (permit the loopback mockchat target, opt 127/8 past the internal-IP deny), the proxy
# drop-in, and the confined probe drop-in, then run the probe. `systemctl start` blocks on the
# Type=oneshot probe and propagates its exit status into PRC (0 == all five checks passed).
SETUP = [
    "EC=/data/bulkhead/audit-egress/provenance.jsonl",
    WAIT_PROXY,
    "systemctl start bulkhead-mockchat.service",
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
    "systemctl daemon-reload",
    "systemctl restart bulkhead-egress-proxy.service",
    "sleep 1",
    "systemctl start bulkhead-agent-confined@egressprobe.service",
    "PRC=$?",
]

# Single-line kv emitters reused in both boots; J abbreviates the probe-journal command so the
# grep lines stay short. Each value is one parseable `key=...` line inside the boot markers.
PROBE_FACTS = [
    'echo "proxy-active=$(systemctl is-active bulkhead-egress-proxy)"',
    'echo "verifyaudit-active=$(systemctl is-active bulkhead-verify-audit)"',
    "J='journalctl -u bulkhead-agent-confined@egressprobe.service --no-pager'",
    "echo \"probe-noroute=$($J 2>/dev/null | grep -c 'PROBE NOROUTE: PASS')\"",
    "echo \"probe-isolated=$($J 2>/dev/null | grep -c 'PROBE ISOLATED: PASS')\"",
    "echo \"probe-proxyok=$($J 2>/dev/null | grep -c 'PROBE PROXY-OK: PASS')\"",
    "echo \"probe-proxydeny=$($J 2>/dev/null | grep -c 'PROBE PROXY-DENY: PASS')\"",
    "echo \"probe-iouring=$($J 2>/dev/null | grep -c 'PROBE IOURING: PASS')\"",
]

PROBE_BOOT1 = SETUP + [
    "echo '<<<BOOT1'",
    "echo \"group-present=$(grep -c '^bulkhead-audit:' /etc/group)\"",
    'echo "seal-active=$(systemctl is-active bulkhead-seal-audit-key)"',
    'echo "probe-rc=$PRC"',
] + PROBE_FACTS + [
    'echo "chain-on-data=$([ -f $EC ] && echo yes || echo no)"',
    'echo "records-b1=$(grep -c . $EC 2>/dev/null || echo 0)"',
    "echo \"dir-perms=$(stat -c '%a %U:%G' /data/bulkhead/audit-egress 2>/dev/null)\"",
    "bulkhead-collector verify-audit $EC >/tmp/va 2>&1",
    "echo \"verify-ok-b1=$(grep -c 'verify-audit: OK' /tmp/va)\"",
    "echo \"domain-b1=$(grep -c 'domain: egress-proxy' /tmp/va)\"",
    "TIP1=$(sed -n 's/.*tip=\\([0-9a-f]*\\).*/\\1/p' /tmp/va)",
    'echo "tip-b1=$TIP1"',
    "printf '%s' \"$TIP1\" > /data/egress-tip-b1.txt",
    "echo 'BOOT1END>>>'",
    "systemctl reboot",
]

PROBE_BOOT2 = [
    "EC=/data/bulkhead/audit-egress/provenance.jsonl",
    # Open the BOOT2 marker BEFORE the probe re-runs, then capture records-before INSIDE it: that
    # persisted count is what proves the boot-1 chain survived the reboot, so it must be read both
    # (a) before SETUP's probe appends boot-2 records, and (b) inside the markers so the parser
    # (which only reads text between <<<BOOT2 and BOOT2END>>>) actually sees it.
    "echo '<<<BOOT2'",
    "echo \"records-before=$(grep -c . $EC 2>/dev/null || echo 0)\"",
] + SETUP[1:] + [
    'echo "probe-rc=$PRC"',
] + PROBE_FACTS + [
    'echo "records-after=$(grep -c . $EC 2>/dev/null || echo 0)"',
    "echo \"file-perms-b2=$(stat -c '%a %U:%G' $EC 2>/dev/null)\"",
    "bulkhead-collector verify-audit $EC >/tmp/va2 2>&1",
    "echo \"verify-ok-b2=$(grep -c 'verify-audit: OK' /tmp/va2)\"",
    "echo \"domain-b2=$(grep -c 'domain: egress-proxy' /tmp/va2)\"",
    "bulkhead-collector verify-audit $EC --since=@/data/egress-tip-b1.txt >/tmp/nr 2>&1",
    "echo \"norewind-b2=$(grep -c 'no-rewind CLEAN' /tmp/nr)\"",
    "echo 'BOOT2END>>>'",
    "poweroff",
]


def main():
    if not os.path.exists(RUNQEMU_TPM):
        print(f"missing {RUNQEMU_TPM}", file=sys.stderr)
        return 2

    tpmstate = os.environ.get("BULKHEAD_TPMSTATE") or tempfile.mkdtemp(prefix="bh-egress-tpm.")
    env = dict(os.environ, BULKHEAD_TPMSTATE=tpmstate)

    # `snapshot`: the wic is attached read-only with writes to a temp overlay that lives for the
    # qemu PROCESS lifetime, so the in-guest reboot still sees boot 1's /data writes; the overlay
    # (and any chain it accreted) is discarded when qemu exits, so runs stay repeatable.
    proc = subprocess.Popen(
        ["bash", RUNQEMU_TPM, "snapshot"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, bufsize=0, env=env,
    )

    def send(s, chunk=16, delay=0.02):
        # Drip-feed in <=FIFO-size chunks: a bulk write overflows the guest 16550 UART RX FIFO
        # (16 bytes, no flow control) and drops characters.
        data = s.encode()
        try:
            for i in range(0, len(data), chunk):
                proc.stdin.write(data[i:i + chunk])
                proc.stdin.flush()
                time.sleep(delay)
        except (BrokenPipeError, ValueError):
            pass

    def send_probe(lines):
        # One short line at a time; a 0.5s gap lets the shell consume each before the next.
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
    dir_perms = kv(b1, "dir-perms") or ""
    fperms_b2 = kv(b2, "file-perms-b2") or ""

    checks = [
        ("BOOT1 captured", bool(m1)),
        ("bulkhead-audit group exists (extrausers)", kv(b1, "group-present") == "1"),
        ("egress proxy active at boot", kv(b1, "proxy-active") == "active"),
        ("seal-audit-key active (seed provisioned)", kv(b1, "seal-active") == "active"),
        ("verify-audit boot gate active (sealed-seed verify passed)", kv(b1, "verifyaudit-active") == "active"),
        ("confined probe ran to success (exit 0)", kv(b1, "probe-rc") == "0"),
        ("probe NOROUTE PASS", kv(b1, "probe-noroute") == "1"),
        ("probe ISOLATED PASS", kv(b1, "probe-isolated") == "1"),
        ("probe PROXY-OK PASS", kv(b1, "probe-proxyok") == "1"),
        ("probe PROXY-DENY PASS", kv(b1, "probe-proxydeny") == "1"),
        ("probe IOURING PASS (io_uring_setup denied, ADR-0033)", kv(b1, "probe-iouring") == "1"),
        ("egress chain persisted on /data", kv(b1, "chain-on-data") == "yes"),
        ("proxy wrote >=1 signed egress record", rec_b1 >= 1),
        ("chain dir is 2770 root:bulkhead-audit", dir_perms.startswith("2770 root:bulkhead-audit")),
        ("verify-audit OK on the /data egress chain (b1)", kv(b1, "verify-ok-b1") == "1"),
        ("audit domain is egress-proxy (b1)", kv(b1, "domain-b1") == "1"),
        ("chain tip recorded", bool(kv(b1, "tip-b1"))),
        ("BOOT2 captured (in-guest reboot succeeded)", bool(m2)),
        # The load-bearing sealed-seed survival assertion: REQUIRE_SEALED_KEY=1 means an active
        # proxy on boot 2 proves the seed persisted on /data and unsealed (else the unit fails CLOSED).
        ("egress proxy ACTIVE after reboot (sealed seed survived + unsealed, fail-closed)", kv(b2, "proxy-active") == "active"),
        ("verify-audit boot gate active after reboot", kv(b2, "verifyaudit-active") == "active"),
        ("egress chain SURVIVED the reboot (records persisted)", rec_before >= rec_b1 and rec_before >= 1),
        ("prior chain file group-writable 0660 bulkhead-audit", fperms_b2.startswith("660 ") and "bulkhead-audit" in fperms_b2),
        ("cross-boot APPEND succeeded (record count grew)", rec_after > rec_before),
        ("probe IOURING PASS after reboot", kv(b2, "probe-iouring") == "1"),
        ("verify-audit OK on the /data egress chain (b2)", kv(b2, "verify-ok-b2") == "1"),
        ("audit domain is egress-proxy (b2)", kv(b2, "domain-b2") == "1"),
        ("no-rewind CLEAN: b2 tip extends b1 tip", kv(b2, "norewind-b2") == "1"),
    ]

    print("\n\n=== bulkhead Yocto egress-proxy /data chain reboot verification ===")
    ok = True
    for name, cond in checks:
        print(("PASS" if cond else "FAIL") + ": " + name)
        ok = ok and cond
    print("YOCTO EGRESS /data REBOOT OK" if ok else "YOCTO EGRESS /data REBOOT INCOMPLETE")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
