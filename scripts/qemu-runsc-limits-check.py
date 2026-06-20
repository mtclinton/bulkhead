#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# ADR-0031 substrate integration — PER-INSTANCE RESOURCE LIMITS (PRODUCTION-READINESS [81]). runsc runs
# rootless with --ignore-cgroups, so the SYSTEMD unit cgroup is the resource boundary: under gVisor the
# in-sandbox agent's memory is backed by the Sentry+gofer HOST processes, which live in the unit's cgroup-v2
# slice. This proves the bulkhead-agent-runsc@ template's MemoryMax/MemoryHigh/MemorySwapMax/TasksMax/CPUQuota
# (a) are CONFIGURED on every instance, and (b) actually BITE: `bulkhead-agent-runsc@probe-memhog` runs the
# agent's memory bomb (default 4096MB target) under the real unit cgroup, and the per-instance MemoryMax
# (512M) OOM-kills it WITHIN its own slice — the agent never reaches its target, the unit fails, and the
# host (PID 1 + the other tiers) survives. So a runaway/hostile substrate agent cannot exhaust host memory.
# Boots the wic (slirp); stdlib + pexpect. No internet/LLM/key needed (the memhog touches no legs).
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

    check("/usr/bin/runsc" in run("command -v runsc; echo done"), "runsc on PATH")

    # ---- (a) STATIC: the per-instance limits are configured on the @ template ------------------------------
    sh = run("systemctl show bulkhead-agent-runsc@probe-memhog.service "
             "-p MemoryMax -p MemoryHigh -p MemorySwapMax -p TasksMax -p CPUQuotaPerSecUSec 2>&1")
    out("\n[systemctl show limits]\n" + sh)
    check("MemoryMax=536870912" in sh, "per-instance MemoryMax=512M configured on the substrate unit")
    check("MemoryHigh=469762048" in sh, "per-instance MemoryHigh=448M configured (soft throttle below the cap)")
    check("MemorySwapMax=0" in sh, "per-instance MemorySwapMax=0 (a memory bomb cannot escape into swap)")
    check("TasksMax=512" in sh, "per-instance TasksMax=512 configured (bounds a fork bomb)")
    check("CPUQuotaPerSecUSec=2s" in sh, "per-instance CPUQuota=200% configured (bounds a CPU spin)")

    # Bring up the legs the launcher binds (the memhog touches none of them, but the unit Requires= the proxy
    # and the launcher binds the leg dirs, so they must exist).
    run("printf '127.0.0.1\\n' > /run/egress-allow-test.conf")
    run("mkdir -p /run/systemd/system/bulkhead-egress-proxy.service.d")
    run("printf '[Service]\\nEnvironment=BULKHEAD_EGRESS_ALLOWLIST=/run/egress-allow-test.conf\\n"
        "Environment=BULKHEAD_EGRESS_ALLOW_INTERNAL_CIDRS=127.0.0.0/8\\n'"
        " > /run/systemd/system/bulkhead-egress-proxy.service.d/10-test.conf")
    run("mkdir -p /run/systemd/system/bulkhead-router.service.d")
    run("printf '[Service]\\nEnvironment=BULKHEAD_LLAMA_URL=http://127.0.0.1:8088\\n'"
        " > /run/systemd/system/bulkhead-router.service.d/90-test-local.conf")
    run("systemctl daemon-reload 2>&1")
    run("systemctl restart bulkhead-egress-proxy.service 2>&1"); run("systemctl restart bulkhead-router.service 2>&1")
    run("sleep 2 2>/dev/null; true")
    check("active" in run("systemctl is-active bulkhead-egress-proxy.service 2>&1"), "egress proxy active (unit Requires= it)")

    # ---- (b) CONTAINMENT: the memhog is OOM-killed WITHIN its slice; the host survives --------------------
    # No drop-in needed: the agent dispatches `probe-memhog` from argv before the instance path, so the
    # instance name itself selects the memory bomb. Default target 4096MB >> the 512M per-instance cap.
    so = run("systemctl reset-failed bulkhead-agent-runsc@probe-memhog.service 2>/dev/null; "
             "systemctl start bulkhead-agent-runsc@probe-memhog.service 2>&1; echo MH_RC=$?", t=150)
    out("\n[memhog start]\n" + so)
    jr = run("journalctl -u bulkhead-agent-runsc@probe-memhog.service --no-pager 2>&1 | tail -40")
    out("\n[memhog journal]\n" + jr)
    res = run("systemctl show bulkhead-agent-runsc@probe-memhog.service -p Result -p ExecMainStatus 2>&1")
    out("\n[memhog result]\n" + res)

    m = re.search(r"MH_RC=(\d+)", so)
    check(bool(m) and int(m.group(1)) != 0, "the memhog unit FAILED — the bomb did not run to completion (it was bounded)")
    check("MEMHOG-START" in jr, "the memhog agent actually ran the bomb inside the substrate jail")
    check("MEMHOG-UNBOUNDED" not in jr,
          "the memhog was KILLED before reaching its target — the per-instance MemoryMax bit (contained)")
    # Host survives the contained OOM: a sibling tier and PID 1 are still up.
    check("active" in run("systemctl is-active bulkhead-egress-proxy.service 2>&1"),
          "a SIBLING tier (egress proxy) survived the contained OOM — the kill was scoped to the agent's slice")
    check("HOSTUP=yes" in run("echo HOSTUP=$(systemctl is-system-running --wait 2>/dev/null >/dev/null; [ -d /proc/1 ] && echo yes || echo no)"),
          "host PID 1 alive after the contained OOM (the bomb did not take down the host)")

    run("systemctl reset-failed bulkhead-agent-runsc@probe-memhog.service 2>/dev/null; true")
    run("runsc --rootless --ignore-cgroups delete -force probe-memhog 2>/dev/null; true")
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
