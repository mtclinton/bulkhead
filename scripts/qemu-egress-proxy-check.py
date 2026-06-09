#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Verify the ADR-0034 increment-1 STRUCTURAL egress boundary live. A confined agent
# (bulkhead-agent-confined@, PrivateNetwork => no-route netns) must reach the outside ONLY
# through the host egress proxy. Boots the wic, points the proxy's allowlist at the loopback
# test target (mockchat on 127.0.0.1:8088, opting 127.0.0.0/8 in), starts the confined probe
# instance, and asserts its four checks pass + the unit exits 0:
#   NOROUTE    direct dial to a public IP fails (no route in the netns)
#   ISOLATED   direct dial to the host-loopback target fails (the agent's own loopback)
#   PROXY-OK   the SAME target IS reachable through the egress proxy (mediated path works)
#   PROXY-DENY a non-allowlisted destination through the proxy is refused
# This needs no internet: the proxy reaches the host loopback; the agent cannot. Stdlib + pexpect.
import pexpect, sys, os, re
BUILD = "/home/work/ideas/bulkhead/yocto/build"
def out(s): sys.stdout.write(s); sys.stdout.flush()
inner = (f"cd {BUILD} && source ../poky/oe-init-build-env . >/dev/null 2>&1 && "
         f"exec runqemu qemux86-64 wic ovmf nographic kvm slirp")
PS = "BHX_PROMPT> "; results = {}; child = None
def check(c, l): results[l] = bool(c); out(f"\n[CHECK] {'PASS' if c else 'FAIL'}: {l}\n")
def login(c):
    c.expect("login:", timeout=300); c.sendline("root")
    i = c.expect(["Password:", r"@qemux86-64:~#"], timeout=60)
    if i == 0: c.sendline(""); c.expect(r"@qemux86-64:~#", timeout=30)
    c.sendline(f"export PS1='{PS}'"); c.expect(PS, timeout=30); c.expect(PS, timeout=30)
try:
    child = pexpect.spawn("/bin/bash", ["-c", inner], timeout=300, encoding="utf-8", codec_errors="replace")
    child.logfile_read = sys.stdout
    login(child)
    def run(c, t=90): child.sendline(c); child.expect(PS, timeout=t); return child.before

    check("active" in run("systemctl is-active bulkhead-egress-proxy.service 2>&1"), "egress proxy active at boot")

    # The loopback HTTP target the proxy will reach (the agent's own loopback won't have it).
    run("systemctl start bulkhead-mockchat.service 2>&1"); run("sleep 1 2>/dev/null; true")
    check("active" in run("systemctl is-active bulkhead-mockchat.service 2>&1"), "mockchat target active (127.0.0.1:8088)")

    # Point the proxy at a test allowlist that permits the loopback target, and opt 127/8 in.
    run("printf '127.0.0.1\\n' > /run/egress-allow-test.conf")
    run("mkdir -p /run/systemd/system/bulkhead-egress-proxy.service.d")
    run("printf '[Service]\\n"
        "Environment=BULKHEAD_EGRESS_ALLOWLIST=/run/egress-allow-test.conf\\n"
        "Environment=BULKHEAD_EGRESS_ALLOW_INTERNAL_CIDRS=127.0.0.0/8\\n'"
        " > /run/systemd/system/bulkhead-egress-proxy.service.d/10-test.conf")
    run("systemctl daemon-reload 2>&1")
    run("systemctl restart bulkhead-egress-proxy.service 2>&1"); run("sleep 1 2>/dev/null; true")
    check("active" in run("systemctl is-active bulkhead-egress-proxy.service 2>&1"), "egress proxy restarted with test allowlist")

    # The confined probe instance: oneshot, with the probe targets.
    run("mkdir -p /run/systemd/system/bulkhead-agent-confined@egressprobe.service.d")
    run("printf '[Service]\\nType=oneshot\\n"
        "Environment=BULKHEAD_PROBE_TARGET=127.0.0.1:8088\\n"
        "Environment=BULKHEAD_PROBE_DENIED=10.255.255.1:80\\n"
        "Environment=BULKHEAD_PROBE_PUBLIC=1.1.1.1:443\\n'"
        " > /run/systemd/system/bulkhead-agent-confined@egressprobe.service.d/10-test.conf")
    run("systemctl daemon-reload 2>&1")
    startout = run("systemctl start bulkhead-agent-confined@egressprobe.service 2>&1; echo START_RC=$?", t=60)
    out("\n[start]\n" + startout)
    jr = run("journalctl -u bulkhead-agent-confined@egressprobe.service --no-pager 2>&1 | tail -30")
    out("\n[probe journal]\n" + jr)

    check("START_RC=0" in startout, "confined probe unit ran to success (all checks passed -> exit 0)")
    for name in ["NOROUTE", "ISOLATED", "PROXY-OK", "PROXY-DENY"]:
        check(bool(re.search(rf"PROBE {name}: PASS", jr)), f"probe {name} PASS")

    # Signed-chain assertion (ADR-0034/0017): the proxy recorded the probe's allow+deny decisions
    # into its Ed25519-signed, hash-chained egress log on /data; verify it (domain resolves to
    # egress-proxy from the audit-egress path; key from the sibling exported pub).
    chain = "/data/bulkhead/audit-egress/provenance.jsonl"
    va = run(f"bulkhead-collector verify-audit {chain} 2>&1; echo VA_RC=$?", t=30)
    out("\n[verify-audit egress chain]\n" + va)
    m = re.search(r"(\d+) record\(s\) verified", va)
    nrec = int(m.group(1)) if m else 0
    check("VA_RC=0" in va and "domain: egress-proxy" in va, "egress chain verifies signed (domain=egress-proxy)")
    check(nrec >= 2, f"proxy signed the probe's egress decisions into the chain ({nrec} record(s))")

    run("systemctl stop bulkhead-mockchat.service 2>&1")
    run("poweroff", t=20)
except Exception as e:
    out(f"\n[harness] EXC {type(e).__name__}: {e}\n")
    if child is not None: out("\n--- buf ---\n" + (child.before or "")[-2000:] + "\n")
finally:
    try: child.expect(pexpect.EOF, timeout=60)
    except Exception: pass
    try: child.close(force=True)
    except Exception: pass
    os.system("pkill -9 qemu-system-x86 2>/dev/null")
out("\n====== RESULTS ======\n")
for k, v in results.items(): out(f"  {'PASS' if v else 'FAIL'}  {k}\n")
ap = bool(results) and all(results.values())
out(f"\nOVERALL: {'ALL PASS' if ap else 'FAILURES'}\n"); sys.exit(0 if ap else 1)
