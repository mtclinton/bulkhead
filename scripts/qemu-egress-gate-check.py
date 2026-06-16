#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# ADR-0034/0017 fail-closed boot gate (security-review R1). The egress proxy is the single mediated
# chokepoint for untrusted web; a forged/gapped /data audit chain must REFUSE it (and transitively the
# agents that Requires= it), exactly as it already refuses the TCB. Before the fix the proxy was only
# Before=-ordered after verify-audit, which does NOT propagate failure, so a tampered chain refused the
# collector but still granted web egress. The fix makes the proxy Requires=bulkhead-selftest (which on
# Yocto Requires= the chain verifier), mirroring the trusted router leg.
#
# This proves it on a single boot without the swtpm reboot rig: Requires= is a START-time dependency, so
# we STOP the gate units, corrupt the egress chain, then `systemctl start` the proxy — systemd re-runs
# verify-audit on the tampered chain, it fails, and the failure cascades (verify-audit -> selftest ->
# proxy -> a confined agent). The CLEAN control (a valid chain restarts the proxy fine) is asserted first.
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

    check("active" in run("systemctl is-active bulkhead-egress-proxy.service 2>&1"), "egress proxy active at boot (clean chain)")
    check("active" in run("systemctl is-active bulkhead-verify-audit.service 2>&1"), "verify-audit boot gate active (clean chain verified)")
    # The fix: the proxy now Requires= the selftest gate (which on Yocto Requires= verify-audit).
    rq = run("systemctl show -p Requires bulkhead-egress-proxy.service 2>&1")
    check("bulkhead-selftest.service" in rq, "FIX WIRED: the proxy Requires= bulkhead-selftest (the fail-closed gate), mirroring the router")

    chain = "/data/bulkhead/audit-egress/provenance.jsonl"
    # Generate at least one real signed egress record so the chain is non-empty (mockchat target on
    # loopback; allow 127/8 past the internal deny), and confirm the CLEAN chain verifies.
    run("systemctl start bulkhead-mockchat.service 2>&1")
    run("printf '127.0.0.1\\n' > /run/egress-allow-test.conf")
    run("mkdir -p /run/systemd/system/bulkhead-egress-proxy.service.d")
    run("printf '[Service]\\nEnvironment=BULKHEAD_EGRESS_ALLOWLIST=/run/egress-allow-test.conf\\n"
        "Environment=BULKHEAD_EGRESS_ALLOW_INTERNAL_CIDRS=127.0.0.0/8\\n'"
        " > /run/systemd/system/bulkhead-egress-proxy.service.d/10-test.conf")
    run("mkdir -p /run/systemd/system/bulkhead-agent-confined@gateprobe.service.d")
    run("printf '[Service]\\nType=oneshot\\nEnvironment=BULKHEAD_PROBE_TARGET=127.0.0.1:8088\\n"
        "Environment=BULKHEAD_PROBE_DENIED=10.255.255.1:80\\nEnvironment=BULKHEAD_PROBE_PUBLIC=1.1.1.1:443\\n'"
        " > /run/systemd/system/bulkhead-agent-confined@gateprobe.service.d/10-test.conf")
    run("systemctl daemon-reload 2>&1"); run("systemctl restart bulkhead-egress-proxy.service 2>&1"); run("sleep 1 2>/dev/null; true")
    run("systemctl start bulkhead-agent-confined@gateprobe.service 2>&1", t=150)
    nrec = re.search(r"NR=(\d+)", run(f"echo NR=$(grep -c . {chain} 2>/dev/null || echo 0)"))
    check(nrec and int(nrec.group(1)) >= 1, "the egress chain has >=1 signed record to tamper")
    va0 = run(f"bulkhead-collector verify-audit {chain} 2>&1; echo VC=$?", t=30)
    check("VC=0" in va0, "CLEAN control: verify-audit OK on the untampered egress chain")
    # CLEAN control: re-evaluating the gate on a VALID chain still permits the proxy.
    run("systemctl stop bulkhead-egress-proxy.service bulkhead-selftest.service bulkhead-verify-audit.service 2>&1")
    cleanrc = run("systemctl start bulkhead-egress-proxy.service 2>&1; echo SRC=$?", t=120)
    check("SRC=0" in cleanrc and "active" in run("systemctl is-active bulkhead-egress-proxy.service 2>&1"),
          "CLEAN control: with a valid chain, the gate PERMITS the proxy to start (no false-brick)")

    # ===== TAMPER: forge a record into the /data egress chain, then re-evaluate the gate. =====
    run(f"printf '%s\\n' '{{\"seq\":999,\"ts\":1,\"comm\":\"forged\",\"hook\":\"connect\",\"decision\":\"allow\",\"mode\":\"dst=evil.invalid:443\",\"prev_hash\":\"00\",\"hash\":\"deadbeef\",\"sig\":\"00\"}}' >> {chain}")
    vat = run(f"bulkhead-collector verify-audit {chain} 2>&1; echo VC=$?", t=30)
    check("VC=0" not in vat, "the forged record makes verify-audit FAIL (the tamper is detectable)")
    # Stop the gate chain so the next start re-evaluates Requires= fresh (Requires= is start-time).
    run("systemctl stop bulkhead-egress-proxy.service bulkhead-selftest.service bulkhead-verify-audit.service 2>&1")
    tamperrc = run("systemctl start bulkhead-egress-proxy.service 2>&1; echo SRC=$?", t=120)
    out("\n[tampered start]\n" + tamperrc)
    check("SRC=0" not in tamperrc, "TAMPER: `systemctl start bulkhead-egress-proxy` FAILED (the fail-closed gate refused it)")
    check("active" not in run("systemctl is-active bulkhead-egress-proxy.service 2>&1") or
          "failed" in run("systemctl is-active bulkhead-egress-proxy.service 2>&1"),
          "TAMPER: the egress proxy is NOT active under a forged chain (untrusted web egress refused)")
    check("failed" in run("systemctl is-active bulkhead-verify-audit.service 2>&1"),
          "TAMPER: verify-audit is in the failed state (the chain verifier tripped)")
    # Transitive: a confined agent Requires= the proxy, so it cannot start either.
    agrc = run("systemctl start bulkhead-agent-confined@gateprobe.service 2>&1; echo ARC=$?", t=60)
    check("ARC=0" not in agrc, "TAMPER (transitive): a confined agent cannot start while the proxy is refused")

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
