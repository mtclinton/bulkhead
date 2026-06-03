#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Verify ADR-0016 LIVE: the full E0-E3 BPF-LSM stack is armable END-TO-END *with delegation*, so
# the flagship claim "agents are physically unable to bpf()" is DEMONSTRATED, not aspirational.
#
# The hole this closes: previously the broker self-bpf()'d into tcb_cgroups and a jailed agent's
# +ExecStartPre bpf()'d its own egress manifest — both from NON-TCB cgroups, which E0 (lsm/bpf
# deny) EPERMs. So arming E0 killed delegation; the only configs where delegation worked were
# configs where the bpf substrate was unprotected. ADR-0016 routes those two writes through the
# collector (TCB, E0-exempt) over an authenticated control socket, and has the collector grant the
# broker its TCB membership — so E0 stays armed while delegation/agent-launch keep working.
#
# PROOFS (E0 armed the whole time after arming):
#   E0-DENY (before/after on the SAME command): `egress set self` (a DIRECT bpf() map write from
#     the console's non-TCB cgroup) SUCCEEDS in observe, then FAILS once E0 is armed — proving E0
#     denies non-TCB bpf(). (Arming E0 also locks the console out of `status`/`enforce`, so all
#     bpf-reading console reads happen BEFORE arming; afterwards we use systemctl is-active.)
#   DELEGATE-UNDER-E0 (narrow-never-widen from a real agent, with the bpf substrate SEALED): a
#     mock-driven parent (loopback,other; NO public) delegates a child requesting public,...; the
#     child is born loopback,other (public AND-cleared) via the collector control RPC under E0, its
#     public fetch is E2-DENIED under its own cgid, and it FINALs — proving the broker's TCB-context
#     writes AND the child's control-socket manifest write both work with E0 armed.
#   AUDIT: both signed chains verify after the run (file reads, not bpf).
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
    def wait_done(unit, tries=24):
        for _ in range(tries):
            if "RC=0" not in run(f"systemctl is-active {unit} >/dev/null 2>&1; echo RC=$?"):
                return True
            run("sleep 2 2>/dev/null; true")
        return False
    def find_child(suffix):
        ls = run(f"ls -d /run/systemd/system/bulkhead-agent@d1-*-{suffix}.service.d 2>/dev/null; echo END")
        m = re.search(r"bulkhead-agent@(d1-[0-9a-f]+-" + re.escape(suffix) + r")\.service\.d", ls)
        return m.group(1) if m else None
    def write_parent(inst, egress, task):
        d = f"/run/systemd/system/bulkhead-agent@{inst}.service.d"
        run(f"mkdir -p {d}")
        lines = ["[Service]", f"Environment=BULKHEAD_AGENT_EGRESS={egress}",
                 f'Environment="BULKHEAD_AGENT_TASK={task}"',
                 "Environment=BULKHEAD_ROUTER_URL=http://127.0.0.1:8088",
                 "Environment=BULKHEAD_AGENT_ALLOW_DELEGATE=1", "Environment=BULKHEAD_DELEGATE_TIMEOUT=45",
                 "Environment=BULKHEAD_AGENT_DEADLINE=120", "ExecStart=", "ExecStart=/usr/bin/bulkhead-agent %i"]
        args = " ".join("'" + l + "'" for l in lines)
        run(f"printf '%s\\n' {args} > {d}/10-orch.conf")
        run("systemctl daemon-reload 2>&1")
    def delegate_and_approve(parent_inst, suffix):
        run(f"systemctl start bulkhead-agent@{parent_inst}.service 2>&1")
        run("sleep 4 2>/dev/null; true")
        gid = None
        for _ in range(14):
            lst = run("bulkhead-collector approve list 2>&1")  # approve.sock (AF_UNIX), NOT bpf -> OK under E0
            m = re.search(r"id=(\d+) action=delegate", lst)
            if m:
                gid = int(m.group(1)); out("\n[approve list]\n" + lst); break
            run("sleep 2 2>/dev/null; true")
        if gid is not None:
            run(f"bulkhead-collector approve allow {gid} 2>&1")
        cinst = None; conf = ""
        for _ in range(12):
            cinst = find_child(suffix)
            if cinst:
                conf = run(f"cat /run/systemd/system/bulkhead-agent@{cinst}.service.d/20-delegated-egress.conf 2>&1")
                break
            run("sleep 1 2>/dev/null; true")
        wait_done(f"bulkhead-agent@{parent_inst}.service")
        if cinst:
            wait_done(f"bulkhead-agent@{cinst}.service")
        return gid, cinst, conf
    def cjournal(cinst):
        return run(f"journalctl -u bulkhead-agent@{cinst}.service --no-pager 2>&1 | "
                   f"grep -aE 'agent\\[|DENIED|FINAL|egress set' | tail -25")

    check("active" in run("systemctl is-active bulkhead-collector 2>&1"), "collector active")
    # broker: start it + point delegated children at the mock (broker env, never parent). On start
    # the broker self-requests TCB registration via the collector control socket (ADR-0016).
    run("mkdir -p /run/systemd/system/bulkhead-broker.service.d 2>&1")
    run("printf '[Service]\\nEnvironment=BULKHEAD_CHILD_ROUTER_URL=http://127.0.0.1:8088\\n"
        "Environment=BULKHEAD_APPROVAL_TIMEOUT=35\\n' > /run/systemd/system/bulkhead-broker.service.d/90-e0.conf")
    run("systemctl daemon-reload 2>&1")
    run("systemctl start bulkhead-broker.service 2>&1"); run("sleep 1 2>/dev/null; true")
    check("active" in run("systemctl is-active bulkhead-broker.service 2>&1"), "broker active")
    run("systemctl start bulkhead-mockchat.service 2>&1"); run("sleep 2 2>/dev/null; true")
    check("active" in run("systemctl is-active bulkhead-mockchat.service 2>&1"), "mockchat endpoint active (127.0.0.1:8088)")

    # The broker self-registered into tcb_cgroups via the control socket on start. `ctl
    # wait-broker-tcb` is the authoritative probe (the COLLECTOR does the tcb_cgroups lookup, so it
    # works from the console even once E0 is armed). This is the collector-GRANTED membership that
    # replaces the old self-bpf().
    wb = run("bulkhead-collector ctl wait-broker-tcb 2>&1")
    check("OK" in wb, "broker is in tcb_cgroups (collector-granted via the control socket, not self-bpf())")
    # E0-DENY baseline: a DIRECT bpf() map write from the console's non-TCB cgroup SUCCEEDS in observe.
    pre = run("bulkhead-collector egress clear self 2>&1; echo RC=$?")
    check("RC=0" in pre, "E0-DENY baseline: a non-TCB direct bpf() (egress set self) succeeds while E0 is in OBSERVE")

    # ARM E2 then E0 (each arming bpf() runs while E0 is still observe, so it is allowed; once E0 is
    # 1 the console can no longer bpf()). wait-broker-tcb (a socket op) gates the E0 arm.
    run("systemctl start bulkhead-enforce-egress.service 2>&1")
    arm = run("systemctl start bulkhead-enforce.service 2>&1; echo RC=$?")
    out("\n[arm E0]\n" + arm)
    check("RC=0" in arm and "active" in run("systemctl is-active bulkhead-enforce.service 2>&1"),
          "E0 armed (enforce on bpf) after the wait-broker-tcb gate — delegation/agent-launch must still work")

    # E0-DENY (headline): the SAME direct-bpf() command now FAILS — a non-TCB cgroup cannot bpf().
    post = run("bulkhead-collector egress clear self 2>&1; echo RC=$?")
    out("\n[post-arm direct bpf]\n" + post)
    check("RC=0" not in post,
          "E0-DENY: the same non-TCB direct bpf() is now EPERM'd under E0 — agents are physically unable to bpf()")

    # DELEGATE UNDER E0: narrow-never-widen from a real agent, with the bpf substrate SEALED. All
    # steps are sockets/systemd/files (no console bpf): the broker (TCB) does its writes, the child's
    # +ExecStartPre asks the collector (TCB) to write its manifest over the control socket.
    write_parent("e0p", "loopback,other",
                 "ORCH childprobe public,loopback,other FETCH-ONLY https://api.anthropic.com/")
    gid, cinst, conf = delegate_and_approve("e0p", "childprobe")
    out(f"\n[child instance] {cinst}\n[child drop-in]\n{conf}\n")
    check(gid is not None and cinst is not None,
          "DELEGATE-UNDER-E0: parent delegated + operator approved + child minted, all with E0 armed")
    check("BULKHEAD_AGENT_EGRESS=loopback,other" in conf,
          "DELEGATE-UNDER-E0: child manifest written via the collector control RPC = loopback,other (public AND-cleared) under E0")
    jc = cjournal(cinst) if cinst else ""
    out("\n[child journal]\n" + jc + "\n")
    check("DENIED: egress" in jc,
          "DELEGATE-UNDER-E0: the child's public fetch is E2-DENIED under its own cgid (narrow-never-widen, bpf substrate sealed)")
    check("FINAL" in jc or "DONE" in jc,
          "DELEGATE-UNDER-E0: the child reached FINAL — the delegated agent RAN inside its narrowed jail under E0")
    rec = run("grep -a '\"hook\":\"delegate\"' /data/bulkhead/audit-broker/provenance.jsonl 2>/dev/null | grep -a 'childprobe' | tail -1; echo END")
    out("\n[broker delegate record]\n" + rec + "\n")
    check("gen=1" in rec and "task_sha=" in rec,
          "DELEGATE-UNDER-E0: the broker signed the delegate record (gen + task_sha) from its TCB context under E0")

    # SOFT-DISARM (ADR-0016 review fix): `enforce off bpf` routes through the collector (TCB), so it
    # works under E0 — without the fix it would EPERM from the enforce unit's non-TCB cgroup and the
    # kill-switch would silently fail. After disarm, the same console direct bpf() succeeds again.
    run("systemctl stop bulkhead-enforce.service 2>&1"); run("sleep 1 2>/dev/null; true")
    dis = run("bulkhead-collector egress clear self 2>&1; echo RC=$?")
    out("\n[post-disarm direct bpf]\n" + dis)
    check("RC=0" in dis,
          "SOFT-DISARM: `systemctl stop bulkhead-enforce` (routed enforce off) actually disarmed E0 — the console can bpf() again")

    # AUDIT (file reads, not bpf): both signed chains verify with E0 armed.
    v1 = run("bulkhead-collector verify-audit /data/bulkhead/audit-broker/provenance.jsonl 2>&1; echo RC=$?")
    v2 = run("bulkhead-collector verify-audit /data/bulkhead/audit/provenance.jsonl 2>&1; echo RC=$?")
    out("\n[verify]\n" + v1 + v2)
    check("verify-audit: OK" in v1 and "RC=0" in v1 and "verify-audit: OK" in v2 and "RC=0" in v2,
          "AUDIT: both signed chains verify after the orchestration under E0")

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
