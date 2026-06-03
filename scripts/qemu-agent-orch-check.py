#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Verify ADR-0015 sub-agent orchestration LIVE: a REAL (mock-driven) parent agent decides to
# spawn a CHILD agent that runs a parent-supplied sub-task, kernel-confined to parent ∩ requested
# egress and audited per-child. The proofs:
#
#   ARM CONFINE (headline / narrow-never-widen from a real agent): a parent (manifest loopback,
#     other; NO public) delegates a child requesting public,loopback,other with a task ordering a
#     public fetch; the operator approves; the child is born loopback,other (public AND-cleared),
#     so its fetch to api.anthropic.com (a floor-ALLOWED public host) is E2-DENIED purely by its
#     BPF manifest, even though the request AND the task demanded public. The child still reaches
#     the router (loopback) and FINALs — the task RAN. The signed broker record names the child
#     instance + gen=1 + task_sha + applied=loopback,other.
#
#   ARM ALLOW (positive control — it's the mask, not a blanket block): a parent that HOLDS public
#     delegates the same; the child keeps public; its fetch is NOT E2-denied.
#
#   ARM INJECTION (the channel neutralizes a sanitizer-passing payload): a parent delegates a
#     child whose task is `FETCH-ONLY ExecStartPre=+/usr/bin/touch /run/pwned` — no control chars,
#     so validTask PASSES. The task rides a credential, never unit syntax: the child launches as a
#     DynamicUser, /run/pwned is NEVER created, the child's .conf carries NO ExecStartPre, and the
#     payload text appears ONLY in the broker-owned /run/bulkhead/tasks/<inst>.task credential
#     source. (Control-char rejection is the host TestValidTask; an agent can only emit one line.)
#
#   ARM AUDIT: both signed chains verify; the broker chain has the delegate record; the child's
#     own E2 verdict lands under its DISTINCT cgid in the collector chain.
#
# Inference is the bundled mockchat (no LLM fits the 256MB/CPU/no-model-disk harness); the agent
# binary is byte-identical to production — only BULKHEAD_ROUTER_URL differs.
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

    # --- a delegating PARENT: a real agent whose task makes it emit ONE delegate directive. ---
    def write_parent(inst, egress, task):
        d = f"/run/systemd/system/bulkhead-agent@{inst}.service.d"
        run(f"mkdir -p {d}")
        # write the drop-in via a heredoc so the (space-bearing, double-quoted) task survives
        run(f"cat > {d}/10-orch.conf <<'EOF'\n"
            f"[Service]\n"
            f"Environment=BULKHEAD_AGENT_EGRESS={egress}\n"
            f'Environment="BULKHEAD_AGENT_TASK={task}"\n'
            f"Environment=BULKHEAD_ROUTER_URL=http://127.0.0.1:8088\n"
            f"Environment=BULKHEAD_AGENT_ALLOW_DELEGATE=1\n"
            f"Environment=BULKHEAD_DELEGATE_TIMEOUT=45\n"
            f"Environment=BULKHEAD_AGENT_DEADLINE=120\n"
            f"ExecStart=\n"
            f"ExecStart=/usr/bin/bulkhead-agent %i\n"
            f"EOF")
        run("systemctl daemon-reload 2>&1")

    def delegate_and_approve(parent_inst, suffix, decision="allow"):
        # start the parent; it delegates within a step or two, then BLOCKS on the operator gate.
        run(f"systemctl start bulkhead-agent@{parent_inst}.service 2>&1")
        run("sleep 4 2>/dev/null; true")
        gid = None
        for _ in range(14):
            lst = run("bulkhead-collector approve list 2>&1")
            m = re.search(r"id=(\d+) action=delegate", lst)
            if m:
                gid = int(m.group(1)); out("\n[approve list]\n" + lst); break
            run("sleep 2 2>/dev/null; true")
        if gid is not None:
            run(f"bulkhead-collector approve {decision} {gid} 2>&1")
        run("sleep 4 2>/dev/null; true")
        wait_done(f"bulkhead-agent@{parent_inst}.service")
        # resolve the broker-minted child instance from its drop-in dir (d1-<hex>-<suffix>).
        ls = run(f"ls -d /run/systemd/system/bulkhead-agent@d1-*-{suffix}.service.d 2>/dev/null; echo END")
        cm = re.search(r"bulkhead-agent@(d1-[0-9a-f]+-" + re.escape(suffix) + r")\.service\.d", ls)
        cinst = cm.group(1) if cm else None
        return gid, cinst
    def cjournal(cinst):
        return run(f"journalctl -u bulkhead-agent@{cinst}.service --no-pager 2>&1 | "
                   f"grep -aE 'agent\\[|DENIED|OK: fetch|FINAL|egress set' | tail -25")

    check("active" in run("systemctl is-active bulkhead-collector 2>&1"), "collector active")
    # the broker is socket-activated; start it explicitly so it self-registers TCB up front, and
    # point delegated CHILDREN at the bundled mock (broker env, never parent — no SSRF-via-infer).
    run("mkdir -p /run/systemd/system/bulkhead-broker.service.d 2>&1")
    run("printf '[Service]\\nEnvironment=BULKHEAD_CHILD_ROUTER_URL=http://127.0.0.1:8088\\n"
        "Environment=BULKHEAD_APPROVAL_TIMEOUT=35\\n' > /run/systemd/system/bulkhead-broker.service.d/90-orch.conf")
    run("systemctl daemon-reload 2>&1")
    run("systemctl start bulkhead-broker.service 2>&1"); run("sleep 1 2>/dev/null; true")
    check("active" in run("systemctl is-active bulkhead-broker.service 2>&1"), "broker active (TCB self-registered)")
    run("systemctl start bulkhead-mockchat.service 2>&1"); run("sleep 2 2>/dev/null; true")
    check("active" in run("systemctl is-active bulkhead-mockchat.service 2>&1"), "mockchat endpoint active (127.0.0.1:8088)")
    arm = run("systemctl start bulkhead-enforce-egress.service 2>&1; echo RC=$?")
    check("RC=0" in arm and "ENFORCE" in run("bulkhead-collector status 2>&1"), "E2 armed (socket_connect ENFORCE)")

    # ===== ARM CONFINE: narrow-never-widen from a real agent decision =====
    write_parent("orchp", "loopback,other",
                 "ORCH childprobe public,loopback,other FETCH-ONLY https://api.anthropic.com/")
    gidC, cinstC = delegate_and_approve("orchp", "childprobe", "allow")
    out(f"\n[child instance] {cinstC}\n")
    check(gidC is not None and cinstC is not None,
          "ARM CONFINE: parent's model loop DECIDED to delegate; operator approved; child d1-*-childprobe minted")
    jC = cjournal(cinstC) if cinstC else ""
    out("\n[child journal]\n" + jC + "\n")
    check("DENIED: egress" in jC,
          "ARM CONFINE: child's fetch to the public host was E2-DENIED — public AND-cleared though the task demanded it (narrow-never-widen)")
    check("FINAL" in jC or "DONE" in jC,
          "ARM CONFINE: the child reached FINAL over loopback — the delegated task RAN inside the narrowed jail")
    # the signed broker record: applied=loopback,other (public dropped), gen=1, a task hash bound.
    rec = run("grep -a '\"hook\":\"delegate\"' /data/bulkhead/audit-broker/provenance.jsonl 2>/dev/null | tail -1; echo END")
    out("\n[broker delegate record]\n" + rec + "\n")
    check("applied=loopback,other" in rec and "gen=1" in rec and "task_sha=" in rec,
          "ARM CONFINE/AUDIT: the signed delegate record binds applied=loopback,other + gen=1 + task_sha (the exact task bytes)")

    # ===== ARM ALLOW (positive control): a public-holding parent => child KEEPS public =====
    write_parent("orchq", "public,loopback,other",
                 "ORCH childopen public,loopback,other FETCH-ONLY https://api.anthropic.com/")
    gidA, cinstA = delegate_and_approve("orchq", "childopen", "allow")
    jA = cjournal(cinstA) if cinstA else ""
    out(f"\n[child-open instance] {cinstA}\n[child-open journal]\n" + jA + "\n")
    check(cinstA is not None and "DENIED: egress" not in jA and ("OK: fetch" in jA or "FINAL" in jA),
          "ARM ALLOW: a public-holding parent's child KEEPS public — its fetch is NOT E2-denied (the mask, not a blanket block)")

    # ===== ARM INJECTION: a sanitizer-passing directive-looking task is channel-neutralized =====
    write_parent("orchx", "loopback,other",
                 "ORCH childpwn loopback,other FETCH-ONLY ExecStartPre=+/usr/bin/touch /run/pwned")
    gidX, cinstX = delegate_and_approve("orchx", "childpwn", "allow")
    out(f"\n[inject child instance] {cinstX}\n")
    check(cinstX is not None, "ARM INJECTION: the directive-looking task PASSED validTask (printable ASCII) and a child was minted")
    pwned = run("test -e /run/pwned && echo PWNED || echo CLEAN")
    check("CLEAN" in pwned, "ARM INJECTION: /run/pwned was NEVER created — the task did not inject a unit directive")
    conf = run(f"cat /run/systemd/system/bulkhead-agent@{cinstX}.service.d/20-delegated-egress.conf 2>&1") if cinstX else ""
    out("\n[child drop-in .conf]\n" + conf + "\n")
    check(cinstX is not None and "ExecStartPre" not in conf and "/run/pwned" not in conf and "touch" not in conf,
          "ARM INJECTION: the child drop-in contains ONLY broker-fixed lines — none of the task bytes reached unit syntax")
    taskfile = run(f"cat /run/bulkhead/tasks/{cinstX}.task 2>&1") if cinstX else ""
    out("\n[credential-source .task file]\n" + taskfile + "\n")
    check(cinstX is not None and "ExecStartPre=+/usr/bin/touch /run/pwned" in taskfile,
          "ARM INJECTION: the payload lives verbatim ONLY as credential CONTENT in /run/bulkhead/tasks/<inst>.task (file, not unit grammar)")
    # the child ran as a DynamicUser (non-root), not as root — the jail held.
    cuser = run(f"systemctl show -p User -p DynamicUser bulkhead-agent@{cinstX}.service 2>&1") if cinstX else ""
    check(cinstX is not None and "DynamicUser=yes" in cuser and "User=root" not in cuser,
          "ARM INJECTION: the child ran as a DynamicUser jail (not root) — no privilege escalation")

    # ===== ARM AUDIT: both chains verify; child verdict under its own cgid =====
    v1 = run("bulkhead-collector verify-audit /data/bulkhead/audit-broker/provenance.jsonl 2>&1; echo RC=$?")
    v2 = run("bulkhead-collector verify-audit /data/bulkhead/audit/provenance.jsonl 2>&1; echo RC=$?")
    out("\n[verify]\n" + v1 + v2)
    check("verify-audit: OK" in v1 and "RC=0" in v1 and "verify-audit: OK" in v2 and "RC=0" in v2,
          "ARM AUDIT: BOTH signed chains verify after the orchestration (every parent + child action is Ed25519-verifiable)")
    st = run("bulkhead-collector status 2>&1"); out("\n[status]\n" + st)

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
