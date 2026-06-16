#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# ADR-0031 substrate integration, slice 3: an agent running UNDER gVisor/runsc keeps its single
# MEDIATED way out. The spike's favorable finding — host-side egress mediation is preserved when the
# agent moves into a Sentry — made concrete: runsc with --host-uds=open lets the sandboxed agent
# reach the HOST egress-proxy UNIX socket, and the host proxy makes the actual egress on its behalf.
# So the structural boundary (no direct egress; the proxy is the only path; the allowlist is enforced)
# holds for an agent under the substrate exactly as it does in the no-route netns jail today.
#
# Setup: the host egress proxy with a test allowlist (permit a loopback target) + a loopback mockchat
# as that target. Then probe-egress under runsc (network=none, host-uds=open) with the egress sock:
#   NOROUTE/ISOLATED — no direct egress from the sandbox (gVisor's network isolation)
#   PROXY-OK        — the loopback target IS reachable THROUGH the host proxy (mediated path crosses
#                     the gVisor boundary via host-uds passthrough)
#   PROXY-DENY      — a non-allowlisted destination through the proxy is refused (allowlist enforced)
#   IOURING         — io_uring is ENOSYS under the Sentry (ADR-0033 ban from the substrate)
# Boots the wic (slirp); stdlib + pexpect.
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
    check("runsc version" in run("runsc --version 2>&1"), "runsc present")

    # A loopback target for the proxy to reach on ALLOW (mockchat listens on 127.0.0.1:8088).
    run("systemctl restart bulkhead-mockchat.service 2>&1"); run("sleep 1 2>/dev/null; true")
    check("active" in run("systemctl is-active bulkhead-mockchat.service 2>&1"), "loopback target (mockchat 127.0.0.1:8088) active")

    # Proxy test allowlist: permit the loopback target + opt 127/8 past the internal-IP deny.
    run("printf '127.0.0.1\\n' > /run/egress-allow-test.conf")
    run("mkdir -p /run/systemd/system/bulkhead-egress-proxy.service.d")
    run("printf '[Service]\\n"
        "Environment=BULKHEAD_EGRESS_ALLOWLIST=/run/egress-allow-test.conf\\n"
        "Environment=BULKHEAD_EGRESS_ALLOW_INTERNAL_CIDRS=127.0.0.0/8\\n'"
        " > /run/systemd/system/bulkhead-egress-proxy.service.d/10-test.conf")
    run("systemctl daemon-reload 2>&1")
    run("systemctl restart bulkhead-egress-proxy.service 2>&1"); run("sleep 1 2>/dev/null; true")
    check("active" in run("systemctl is-active bulkhead-egress-proxy.service 2>&1"), "egress proxy restarted with test allowlist")
    sock = run("echo ESOCK=$(ls /run/bulkhead-egress/egress.sock 2>/dev/null && echo yes)")
    check("egress.sock" in sock, "the host egress-proxy UDS exists (/run/bulkhead-egress/egress.sock)")

    chain = "/data/bulkhead/audit-egress/provenance.jsonl"
    nb = re.search(r"NB=(\d+)", run(f"echo NB=$(grep -c '\"hook\":\"connect\"' {chain} 2>/dev/null || echo 0)"))
    nbefore = int(nb.group(1)) if nb else -1

    # Run probe-egress UNDER gVisor with --host-uds=open, pointing BULKHEAD_EGRESS_SOCK at the host
    # proxy UDS (visible via runsc do's readonly host mount). network=none => no direct egress; the
    # ONLY way out is the proxy UDS, proxied across the Sentry boundary to the host.
    rc = ("runsc --host-uds=open --rootless --ignore-cgroups --platform=systrap --network=none do /bin/sh -c '"
          "echo KVER=$(uname -r); "
          "BULKHEAD_EGRESS_SOCK=/run/bulkhead-egress/egress.sock "
          "BULKHEAD_PROBE_TARGET=127.0.0.1:8088 "
          "BULKHEAD_PROBE_DENIED=10.255.255.1:80 "
          "/usr/bin/bulkhead-agent probe-egress 2>&1'")
    ao = run(rc, t=150)
    out(f"\n[agent probe-egress under runsc + host-uds]\n{ao}\n")

    check(bool(re.search(r"KVER=4\.4", ao)), "the agent ran UNDER gVisor (sandbox kernel 4.4.x)")
    check("PROBE NOROUTE: PASS" in ao, "NOROUTE — no direct public egress from the sandbox")
    check("PROBE ISOLATED: PASS" in ao, "ISOLATED — the sandbox loopback is isolated from the host")
    check("PROBE PROXY-OK: PASS" in ao,
          "PROXY-OK — the loopback target IS reachable THROUGH the host egress proxy (mediated path crosses the gVisor boundary)")
    check("PROBE PROXY-DENY: PASS" in ao,
          "PROXY-DENY — a non-allowlisted destination is refused by the proxy allowlist (enforced for the agent-under-gVisor)")
    check("PROBE IOURING: PASS" in ao, "IOURING — io_uring denied by the Sentry (ENOSYS)")

    # The proxy SIGNED the agent-under-gVisor's allowed egress into its /data chain, same as a jailed agent.
    na = re.search(r"NA=(\d+)", run(f"echo NA=$(grep -c '\"hook\":\"connect\"' {chain} 2>/dev/null || echo 0)"))
    nafter = int(na.group(1)) if na else -1
    va = run(f"bulkhead-collector verify-audit {chain} 2>&1; echo VA_RC=$?", t=30)
    check(nbefore >= 0 and nafter > nbefore,
          f"the agent-under-gVisor's mediated egress was SIGNED into the egress chain ({nbefore} -> {nafter})")
    check("VA_RC=0" in va and "domain: egress-proxy" in va, "the egress chain still verifies signed (domain=egress-proxy)")

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
