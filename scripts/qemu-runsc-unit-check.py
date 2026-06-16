#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# ADR-0031 substrate integration, slice 6: the DEPLOYABLE form. An operator launches a substrate-jailed
# agent with `systemctl start bulkhead-agent-runsc@<inst>` — no hand-crafted runsc invocation. The unit
# ExecStarts the bulkhead-agent-runsc-launch helper, which builds a per-instance minimal-rootfs OCI
# bundle (only the agent + UDS legs + task credential bind-mounted; host fs not exposed) and `runsc
# run`s it. This proves the whole packaged path: unit -> launcher -> runsc run -> a real agent loop
# under gVisor with both mediated legs, the task delivered injection-safely as a credential.
# Boots the wic (slirp); stdlib + pexpect. No internet/LLM/key (mockchat is the canned upstream).
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
    check("bulkhead-agent-runsc-launch" in run("ls /usr/bin/bulkhead-agent-runsc-launch 2>&1"), "the substrate-agent launcher is installed")
    check(bool(re.search(r"bulkhead-agent-runsc-launch", run("systemctl cat bulkhead-agent-runsc@.service 2>&1"))),
          "bulkhead-agent-runsc@.service is installed and ExecStarts the launcher")

    # Model + web backends (mockchat is the canned upstream and the loopback fetch target).
    run("mkdir -p /run/systemd/system/bulkhead-mockchat.service.d")
    run("printf '[Service]\\nEnvironment=BULKHEAD_MOCKCHAT_TARGET=http://127.0.0.1:8088/v1/chat/completions\\n'"
        " > /run/systemd/system/bulkhead-mockchat.service.d/10-target.conf")
    run("systemctl daemon-reload 2>&1"); run("systemctl restart bulkhead-mockchat.service 2>&1"); run("sleep 1 2>/dev/null; true")
    check("active" in run("systemctl is-active bulkhead-mockchat.service 2>&1"), "mockchat upstream active")
    run("mkdir -p /run/systemd/system/bulkhead-router.service.d")
    run("printf '[Service]\\nEnvironment=BULKHEAD_LLAMA_URL=http://127.0.0.1:8088\\n'"
        " > /run/systemd/system/bulkhead-router.service.d/90-test-local.conf")
    run("systemctl daemon-reload 2>&1"); run("systemctl restart bulkhead-router.service 2>&1"); run("sleep 2 2>/dev/null; true")
    check("RUDS=yes" in run("echo RUDS=$([ -S /run/bulkhead-router/router.sock ] && echo yes || echo no)"), "router UDS exists")
    run("printf '127.0.0.1\\n' > /run/egress-allow-test.conf")
    run("mkdir -p /run/systemd/system/bulkhead-egress-proxy.service.d")
    run("printf '[Service]\\nEnvironment=BULKHEAD_EGRESS_ALLOWLIST=/run/egress-allow-test.conf\\n"
        "Environment=BULKHEAD_EGRESS_ALLOW_INTERNAL_CIDRS=127.0.0.0/8\\n'"
        " > /run/systemd/system/bulkhead-egress-proxy.service.d/10-test.conf")
    run("systemctl daemon-reload 2>&1"); run("systemctl restart bulkhead-egress-proxy.service 2>&1"); run("sleep 1 2>/dev/null; true")
    check("active" in run("systemctl is-active bulkhead-egress-proxy.service 2>&1"), "egress proxy active with test allowlist")

    chain = "/data/bulkhead/audit-egress/provenance.jsonl"
    nb = re.search(r"NB=(\d+)", run(f"echo NB=$(grep -c '\"hook\":\"connect\"' {chain} 2>/dev/null || echo 0)"))
    nbefore = int(nb.group(1)) if nb else -1

    # DEPLOY: set the task + `systemctl start` the substrate-jailed agent. oneshot blocks on the run.
    run("mkdir -p /run/systemd/system/bulkhead-agent-runsc@ru.service.d")
    run("printf '[Service]\\nEnvironment=\"BULKHEAD_AGENT_TASK=FETCH-ONLY run\"\\n'"
        " > /run/systemd/system/bulkhead-agent-runsc@ru.service.d/10-task.conf")
    run("systemctl daemon-reload 2>&1")
    so = run("systemctl start bulkhead-agent-runsc@ru.service 2>&1; echo START_RC=$?", t=180)
    out("\n[systemctl start]\n" + so)
    jr = run("journalctl -u bulkhead-agent-runsc@ru.service --no-pager 2>&1 | tail -40")
    out("\n[unit journal]\n" + jr)

    check("START_RC=0" in so, "`systemctl start bulkhead-agent-runsc@ru` ran the substrate-jailed agent to success")
    check(bool(re.search(r"agent\[ru\]: DONE", jr)),
          "the agent loop reached DONE under the runsc unit — model leg over the router UDS worked")
    check("OK: fetch 127.0.0.1:8088 -> HTTP 200" in jr,
          "the web leg fetched THROUGH the egress proxy (HTTP 200) from inside the substrate jail")
    na = re.search(r"NA=(\d+)", run(f"echo NA=$(grep -c '\"hook\":\"connect\"' {chain} 2>/dev/null || echo 0)"))
    nafter = int(na.group(1)) if na else -1
    va = run(f"bulkhead-collector verify-audit {chain} 2>&1; echo VA_RC=$?", t=30)
    check(nbefore >= 0 and nafter > nbefore, f"the substrate-jailed agent's egress was SIGNED into the chain ({nbefore} -> {nafter})")
    check("VA_RC=0" in va and "domain: egress-proxy" in va, "the egress chain still verifies signed")
    # The transient bundle is reaped on stop (no leak).
    check("BUNDLE=gone" in run("systemctl stop bulkhead-agent-runsc@ru.service 2>&1; echo BUNDLE=$([ ! -e /run/bulkhead-runsc/ru ] && echo gone || echo left)"),
          "the per-instance OCI bundle is reaped when the unit stops (no /run leak)")

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
