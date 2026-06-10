#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Verify a REAL bulkhead agent runtime running inside the ADR-0034 confined jail (follow-up to
# inc1, which only ran the probe-egress vehicle there). This proves the structural-egress +
# signed-provenance stack hosts an actual tool-using agent doing real work — not just a probe:
#
#   - The confined jail (bulkhead-agent-confined@, PrivateNetwork => no-route netns) runs the
#     REAL agent loop (bulkhead-agent <inst>, not probe-egress), with a FETCH-ONLY task.
#   - Its MODEL leg has only one path out of the netns: the bind-mounted router UDS. The router
#     (on the host) is pointed at mockchat as its local backend, so the loop gets canned
#     completions over the UDS — exercising the trusted model channel end to end.
#   - Its WEB leg has only one path: the host egress proxy. The model tells it to fetch a
#     loopback URL; the fetch tunnels through the proxy (allowlisted), which signs the ALLOW
#     into its Ed25519 hash-chained /data egress log.
#   - We assert: the loop reached FINAL (exit 0), the fetch returned HTTP 200 THROUGH the proxy,
#     and the proxy appended a freshly-signed record to the egress chain (domain=egress-proxy).
#
# i.e. a real agent whose ONLY ways out — model and web — are the mediated, audited channels.
# No internet, no LLM, no API key needed: mockchat is the canned upstream; the agent binary is
# byte-identical to production. Boots the wic (slirp); stdlib + pexpect.
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
    check("active" in run("systemctl is-active bulkhead-router.service 2>&1"), "router active at boot")

    # mockchat is the canned upstream. Point its scripted FETCH-ONLY target at a LOOPBACK url so the
    # agent's fetch lands on an allowlisted destination the proxy can reach (and sign).
    run("mkdir -p /run/systemd/system/bulkhead-mockchat.service.d")
    run("printf '[Service]\\nEnvironment=BULKHEAD_MOCKCHAT_TARGET=http://127.0.0.1:8088/v1/chat/completions\\n'"
        " > /run/systemd/system/bulkhead-mockchat.service.d/10-target.conf")
    run("systemctl daemon-reload 2>&1")
    run("systemctl restart bulkhead-mockchat.service 2>&1"); run("sleep 1 2>/dev/null; true")
    check("active" in run("systemctl is-active bulkhead-mockchat.service 2>&1"), "mockchat upstream active (127.0.0.1:8088)")

    # Point the ROUTER's local backend at mockchat. The confined agent dials the router UDS and
    # sends route=local; proxyLocal then POSTs to ${LLAMA_URL}/v1/chat/completions == mockchat.
    run("mkdir -p /run/systemd/system/bulkhead-router.service.d")
    run("printf '[Service]\\nEnvironment=BULKHEAD_LLAMA_URL=http://127.0.0.1:8088\\n'"
        " > /run/systemd/system/bulkhead-router.service.d/90-test-local.conf")
    run("systemctl daemon-reload 2>&1")
    run("systemctl restart bulkhead-router.service 2>&1"); run("sleep 2 2>/dev/null; true")
    # Regression guards for the AF_UNIX fix: after settling the router must be STILL active (not
    # crash-looping on the UDS listen) AND its UDS must exist on the host. Before the fix the router
    # EAFNOSUPPORT-crashed on net.Listen("unix"), flapped, and /run/bulkhead-router was never created.
    check("RSTATE=active" in run("echo RSTATE=$(systemctl is-active bulkhead-router.service)"), "router stable after restart (no UDS crash-loop)")
    check("RUDS=yes" in run("echo RUDS=$([ -S /run/bulkhead-router/router.sock ] && echo yes || echo no)"), "router created its UDS for the jail (/run/bulkhead-router/router.sock)")

    # Proxy test allowlist: permit the loopback fetch target and opt 127/8 past the internal-IP deny.
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
    before = run(f"echo REC_BEFORE=$(grep -c . {chain} 2>/dev/null || echo 0)")
    mb = re.search(r"REC_BEFORE=(\d+)", before); nbefore = int(mb.group(1)) if mb else -1

    # The confined REAL agent: override ExecStart from probe-egress to the real loop + a task. Type
    # oneshot so `systemctl start` blocks on the loop and propagates its exit status. The task is
    # QUOTED (it has a space) so systemd does not split it into two Environment= assignments.
    run("mkdir -p /run/systemd/system/bulkhead-agent-confined@confagent.service.d")
    run("printf '[Service]\\nType=oneshot\\nExecStart=\\n"
        "ExecStart=/usr/bin/bulkhead-agent confagent\\n"
        "Environment=\"BULKHEAD_AGENT_TASK=FETCH-ONLY run\"\\n'"
        " > /run/systemd/system/bulkhead-agent-confined@confagent.service.d/10-real.conf")
    run("systemctl daemon-reload 2>&1")
    startout = run("systemctl start bulkhead-agent-confined@confagent.service 2>&1; echo START_RC=$?", t=150)
    out("\n[start]\n" + startout)
    jr = run("journalctl -u bulkhead-agent-confined@confagent.service --no-pager 2>&1 | tail -40")
    out("\n[agent journal]\n" + jr)

    check("START_RC=0" in startout, "confined REAL agent ran to success (reached FINAL -> exit 0)")
    check(bool(re.search(r"agent\[confagent\]: DONE", jr)), "real agent loop completed (DONE) — not the probe")
    check(bool(re.search(r"step \d+ FINAL", jr)), "loop terminated on a model FINAL directive")
    check(bool(re.search(r"TOOL fetch", jr)), "model loop drove a fetch over the router-UDS leg")
    # The model leg has no path but the router UDS in this no-route netns, so reaching FINAL (which
    # needs completions) proves the trusted model channel worked; this asserts the WEB leg delivered.
    check(bool(re.search(r"OK: fetch 127\.0\.0\.1:8088 -> HTTP 200", jr)), "fetch delivered HTTP 200 THROUGH the egress proxy")

    # The fetch's ALLOW was signed into the egress chain (record count grew + chain still verifies).
    after = run(f"echo REC_AFTER=$(grep -c . {chain} 2>/dev/null || echo 0)")
    ma = re.search(r"REC_AFTER=(\d+)", after); nafter = int(ma.group(1)) if ma else -1
    va = run(f"bulkhead-collector verify-audit {chain} 2>&1; echo VA_RC=$?", t=30)
    out("\n[verify-audit egress chain]\n" + va)
    check("VA_RC=0" in va and "domain: egress-proxy" in va, "egress chain verifies signed (domain=egress-proxy)")
    check(nbefore >= 0 and nafter > nbefore, f"agent's fetch was signed into the egress chain ({nbefore} -> {nafter} record(s))")

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
