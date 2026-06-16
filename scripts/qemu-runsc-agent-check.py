#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# ADR-0031 substrate integration, slice 4: a FULL real agent loop runs under gVisor/runsc with BOTH
# of its mediated channels intact — the trusted MODEL leg (the router UDS) and the untrusted WEB leg
# (the egress proxy UDS), each reached across the Sentry boundary via host-uds passthrough. This is
# the confined-jail agent (model over the router UDS, web over the egress proxy, signed) but hosted
# by the substrate instead of the no-route netns. Proves the substrate hosts a real working agent,
# not just a probe: the perceive->decide->act loop reaches FINAL using the router for inference and
# the proxy for its fetch, and the egress is signed into the /data chain.
# Boots the wic (slirp); stdlib + pexpect. No internet/LLM/key: mockchat is the canned upstream.
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

    check("runsc version" in run("runsc --version 2>&1"), "runsc present")
    check("active" in run("systemctl is-active bulkhead-egress-proxy.service 2>&1"), "egress proxy active at boot")
    check("active" in run("systemctl is-active bulkhead-router.service 2>&1"), "router active at boot")

    # mockchat is the canned upstream AND the fetch target (a loopback 200).
    run("mkdir -p /run/systemd/system/bulkhead-mockchat.service.d")
    run("printf '[Service]\\nEnvironment=BULKHEAD_MOCKCHAT_TARGET=http://127.0.0.1:8088/v1/chat/completions\\n'"
        " > /run/systemd/system/bulkhead-mockchat.service.d/10-target.conf")
    run("systemctl daemon-reload 2>&1")
    run("systemctl restart bulkhead-mockchat.service 2>&1"); run("sleep 1 2>/dev/null; true")
    check("active" in run("systemctl is-active bulkhead-mockchat.service 2>&1"), "mockchat upstream active (127.0.0.1:8088)")

    # Point the ROUTER's local backend at mockchat, so the agent's model leg (router UDS) gets canned completions.
    run("mkdir -p /run/systemd/system/bulkhead-router.service.d")
    run("printf '[Service]\\nEnvironment=BULKHEAD_LLAMA_URL=http://127.0.0.1:8088\\n'"
        " > /run/systemd/system/bulkhead-router.service.d/90-test-local.conf")
    run("systemctl daemon-reload 2>&1")
    run("systemctl restart bulkhead-router.service 2>&1"); run("sleep 2 2>/dev/null; true")
    check("RUDS=yes" in run("echo RUDS=$([ -S /run/bulkhead-router/router.sock ] && echo yes || echo no)"),
          "the router UDS exists for the agent (/run/bulkhead-router/router.sock)")

    # Egress proxy test allowlist: permit the loopback fetch target.
    run("printf '127.0.0.1\\n' > /run/egress-allow-test.conf")
    run("mkdir -p /run/systemd/system/bulkhead-egress-proxy.service.d")
    run("printf '[Service]\\n"
        "Environment=BULKHEAD_EGRESS_ALLOWLIST=/run/egress-allow-test.conf\\n"
        "Environment=BULKHEAD_EGRESS_ALLOW_INTERNAL_CIDRS=127.0.0.0/8\\n'"
        " > /run/systemd/system/bulkhead-egress-proxy.service.d/10-test.conf")
    run("systemctl daemon-reload 2>&1")
    run("systemctl restart bulkhead-egress-proxy.service 2>&1"); run("sleep 1 2>/dev/null; true")
    check("active" in run("systemctl is-active bulkhead-egress-proxy.service 2>&1"), "egress proxy restarted with test allowlist")

    chain = "/data/bulkhead/audit-egress/provenance.jsonl"
    nb = re.search(r"NB=(\d+)", run(f"echo NB=$(grep -c '\"hook\":\"connect\"' {chain} 2>/dev/null || echo 0)"))
    nbefore = int(nb.group(1)) if nb else -1

    # Run the REAL agent loop UNDER gVisor: model over the router UDS, web over the egress proxy UDS,
    # both reached via host-uds passthrough. --network=none => no direct egress; the only ways out are
    # the two mediated UDS legs.
    ac = ("runsc --host-uds=open --rootless --ignore-cgroups --platform=systrap --network=none do /bin/sh -c '"
          "echo KVER=$(uname -r); "
          "BULKHEAD_ROUTER_UDS=/run/bulkhead-router/router.sock "
          "BULKHEAD_EGRESS_SOCK=/run/bulkhead-egress/egress.sock "
          "BULKHEAD_AGENT_TASK=\"FETCH-ONLY run\" "
          "BULKHEAD_AGENT_DEADLINE=60 "
          "/usr/bin/bulkhead-agent runscagent 2>&1; echo AGENT_RC=$?'")
    ao = run(ac, t=180)
    out(f"\n[real agent loop under runsc]\n{ao}\n")

    check(bool(re.search(r"KVER=4\.4", ao)), "the agent loop ran UNDER gVisor (sandbox kernel 4.4.x)")
    check(bool(re.search(r"agent\[runscagent\]: DONE", ao)),
          "the agent loop reached DONE — the MODEL leg worked (inference over the router UDS, across the Sentry)")
    check(bool(re.search(r"step \d+ FINAL", ao)), "the loop terminated on a model FINAL directive")
    check("OK: fetch 127.0.0.1:8088 -> HTTP 200" in ao,
          "the WEB leg worked: the agent's fetch went THROUGH the egress proxy (HTTP 200), across the Sentry")

    # The mediated egress was signed into the /data chain, same as a netns-jailed agent.
    na = re.search(r"NA=(\d+)", run(f"echo NA=$(grep -c '\"hook\":\"connect\"' {chain} 2>/dev/null || echo 0)"))
    nafter = int(na.group(1)) if na else -1
    va = run(f"bulkhead-collector verify-audit {chain} 2>&1; echo VA_RC=$?", t=30)
    check(nbefore >= 0 and nafter > nbefore, f"the agent-under-gVisor's fetch was SIGNED into the egress chain ({nbefore} -> {nafter})")
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
