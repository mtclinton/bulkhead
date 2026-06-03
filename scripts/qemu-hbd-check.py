#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Verify ADR-0018 HARDEN-BY-DEFAULT LIVE: the shipped image boots E0-ARMED (lsm/bpf deny) + E2-ARMED
# (per-agent egress) with NO operator action — converting ADR-0016's "armable+opt-in" into "enforced
# out of the box". Unlike qemu-e0-check.py (which IMPERATIVELY arms then tests = proves ARMABLE),
# this does ZERO `systemctl start broker/enforce`, REBOOTS once, and asserts the armed posture from a
# cold boot — the distinguishing BOOTS-ARMED proof. The broker is boot-started and handed the
# bulkhead-broker.socket fd (LISTEN_FDS), so it is up + collector-TCB-registered before the enforce
# gate; a fail-closed brokerListener means it never steals the socket.
import pexpect, sys, os, re
BUILD = "/home/work/ideas/bulkhead/yocto/build"
def out(s): sys.stdout.write(s); sys.stdout.flush()
inner = (f"cd {BUILD} && source ../poky/oe-init-build-env . >/dev/null 2>&1 && "
         f"exec runqemu qemux86-64 wic ovmf nographic kvm slirp")
PS = "BHX_PROMPT> "; results = {}; child = None
def check(c, l): results[l] = bool(c); out(f"\n[CHECK] {'PASS' if c else 'FAIL'}: {l}\n")
try:
    child = pexpect.spawn("/bin/bash", ["-c", inner], timeout=300, encoding="utf-8", codec_errors="replace")
    child.logfile_read = sys.stdout
    def login():
        child.expect("login:", timeout=300); child.sendline("root")
        i = child.expect(["Password:", r"@qemux86-64:~#"], timeout=60)
        if i == 0: child.sendline(""); child.expect(r"@qemux86-64:~#", timeout=30)
        child.sendline(f"export PS1='{PS}'"); child.expect(PS, timeout=30); child.expect(PS, timeout=30)
    login()
    def run(c, t=90): child.sendline(c); child.expect(PS, timeout=t); return child.before
    # use the EXIT CODE, not "active" in the output — the command echo contains "is-active", which
    # would make a substring check a false positive for a failed/inactive unit. `is-active` exits 0
    # only when the unit is genuinely active.
    def is_active(u): return "RC=0" in run(f"systemctl is-active {u} >/dev/null 2>&1; echo RC=$?")
    def armed_from_cold_boot(tag):
        # is-active reads (NOT bpf) work under E0; the broker + both enforce units auto-armed at boot.
        e0 = is_active("bulkhead-enforce.service"); e2 = is_active("bulkhead-enforce-egress.service")
        bk = is_active("bulkhead-broker.service")
        check(e0 and e2 and bk, f"{tag}: E0 + E2 + broker all ACTIVE from cold boot (enforced out of the box, no operator action)")
        # the headline: a non-TCB console direct bpf() is EPERM'd — with NO prior arm command.
        d = run("bulkhead-collector egress clear self 2>&1; echo RC=$?")
        check("RC=0" not in d, f"{tag}: a non-TCB direct bpf() (egress clear self) is EPERM'd under E0 — armed at boot, not by the harness")

    # ===== ARM 1+2: armed from the FIRST cold boot, broker took the socket fd (no path-steal) =====
    check(is_active("bulkhead-collector.service"), "collector active (cold boot)")
    armed_from_cold_boot("COLD-BOOT-1")
    bj = run("journalctl -u bulkhead-broker.service --no-pager 2>&1 | grep -a 'broker: armed' | tail -2")
    out("\n[broker journal]\n" + bj + "\n")
    # "broker: armed" is logged ONLY after brokerListener() succeeds (took the LISTEN_FDS fd) AND
    # brokerRegisterTCB() returned — a fail-closed/refused bind log.Fatalf's before this line.
    nofc = run("journalctl -u bulkhead-broker.service --no-pager 2>&1 | grep -ac 'no LISTEN_FDS'; echo END")
    wb = run("bulkhead-collector ctl wait-broker-tcb 2>&1")
    check("broker: armed" in bj and "OK" in wb and any(t == "0" for t in nofc.replace("END", " ").split()),
          "ARM 2: the broker boot-started, took the bulkhead-broker.socket fd (no fail-closed refusal), and is collector-TCB-registered")

    # ===== ARM 4: REBOOT, re-assert armed-from-cold-boot (deterministic default, not a fluke) =====
    out("\n[rebooting]\n"); child.sendline("systemctl reboot")
    login()  # ride the reboot back to a fresh login
    check(is_active("bulkhead-collector.service"), "collector active (after reboot)")
    armed_from_cold_boot("REBOOT")

    # ===== ARM 5: delegation narrow-never-widen UNDER cold-boot-E0 (broker writes via control RPC) =====
    # The broker boot-started WITHOUT the demo's child-router drop-in; apply it + restart the broker
    # (it re-takes the socket fd via LISTEN_FDS and re-registers TCB — a control RPC, not bpf, so OK
    # under E0). Then a mock-driven parent delegates a child confined to parent ∩ requested.
    run("systemctl start bulkhead-mockchat.service 2>&1"); run("sleep 2 2>/dev/null; true")
    check(is_active("bulkhead-mockchat.service"), "mockchat endpoint active (127.0.0.1:8088)")
    run("mkdir -p /run/systemd/system/bulkhead-broker.service.d 2>&1")
    run("printf '[Service]\\nEnvironment=BULKHEAD_CHILD_ROUTER_URL=http://127.0.0.1:8088\\n"
        "Environment=BULKHEAD_APPROVAL_TIMEOUT=35\\n' > /run/systemd/system/bulkhead-broker.service.d/90-hbd.conf")
    run("systemctl daemon-reload 2>&1"); run("systemctl restart bulkhead-broker.service 2>&1"); run("sleep 2 2>/dev/null; true")
    check(is_active("bulkhead-broker.service") and "OK" in run("bulkhead-collector ctl wait-broker-tcb 2>&1"),
          "ARM 5: broker restarted (re-took the socket fd + re-registered TCB) under armed E0")
    d = "/run/systemd/system/bulkhead-agent@hbdp.service.d"; run(f"mkdir -p {d}")
    lines = ["[Service]", "Environment=BULKHEAD_AGENT_EGRESS=loopback,other",
             'Environment="BULKHEAD_AGENT_TASK=ORCH childprobe public,loopback,other FETCH-ONLY https://api.anthropic.com/"',
             "Environment=BULKHEAD_ROUTER_URL=http://127.0.0.1:8088", "Environment=BULKHEAD_AGENT_ALLOW_DELEGATE=1",
             "Environment=BULKHEAD_DELEGATE_TIMEOUT=45", "Environment=BULKHEAD_AGENT_DEADLINE=120",
             "ExecStart=", "ExecStart=/usr/bin/bulkhead-agent %i"]
    run("printf '%s\\n' " + " ".join("'" + l + "'" for l in lines) + f" > {d}/10-hbd.conf")
    run("systemctl daemon-reload 2>&1")
    run("systemctl start bulkhead-agent@hbdp.service 2>&1"); run("sleep 4 2>/dev/null; true")
    gid = None
    for _ in range(14):
        lst = run("bulkhead-collector approve list 2>&1")
        m = re.search(r"id=(\d+) action=delegate", lst)
        if m: gid = int(m.group(1)); out("\n[approve]\n" + lst); break
        run("sleep 2 2>/dev/null; true")
    if gid is not None: run(f"bulkhead-collector approve allow {gid} 2>&1")
    cinst = None; conf = ""
    for _ in range(12):
        ls = run("ls -d /run/systemd/system/bulkhead-agent@d1-*-childprobe.service.d 2>/dev/null; echo END")
        cm = re.search(r"bulkhead-agent@(d1-[0-9a-f]+-childprobe)\.service\.d", ls)
        if cm:
            cinst = cm.group(1)
            conf = run(f"cat /run/systemd/system/bulkhead-agent@{cinst}.service.d/20-delegated-egress.conf 2>&1"); break
        run("sleep 1 2>/dev/null; true")
    # the child's bounded loop (mock inference -> fetch[denied] -> FINAL) finishes in seconds; a
    # generous fixed wait avoids an is-active race that treats "activating" as finished and greps
    # an empty journal. Capture the FULL agent journal for the assertion + diagnosis.
    run("sleep 18 2>/dev/null; true")
    jc = run(f"journalctl -u bulkhead-agent@{cinst}.service --no-pager 2>&1 | grep -aE 'agent\\[|DENIED|FINAL|egress|control|Failed' | tail -25") if cinst else ""
    out(f"\n[child {cinst}]\n{conf}\n[child journal]\n{jc}\n")
    check(gid is not None and cinst is not None and "BULKHEAD_AGENT_EGRESS=loopback,other" in conf,
          "ARM 5: delegated child born loopback,other (public AND-cleared) via the collector control RPC, with E0 armed since boot")
    check("DENIED: egress" in jc and "FINAL" in jc,
          "ARM 5: child's public fetch E2-DENIED (E2 armed at boot) + child FINALed — narrow-never-widen under cold-boot enforcement")

    # ===== ARM 6: collector restart — degrade-to-observe then RECONVERGE to armed, never brick =====
    run("systemctl restart bulkhead-collector.service 2>&1"); run("sleep 3 2>/dev/null; true")
    ok = False
    for _ in range(20):
        if "OK" in run("bulkhead-collector ctl wait-broker-tcb 2>&1") and is_active("bulkhead-enforce.service"):
            ok = True; break
        run("sleep 2 2>/dev/null; true")
    sock = run("test -S /run/bulkhead/control.sock && echo HAVE || echo GONE")
    redeny = run("bulkhead-collector egress clear self 2>&1; echo RC=$?")
    check(ok and "HAVE" in sock and "RC=0" not in redeny,
          "ARM 6: after a collector restart, E0 re-armed (broker re-registered, PartOf re-arm) + control.sock survived — reconverged, never bricked")

    # ===== ARM 7: SOFT-DISARM under cold-boot-E0 (routed enforce-off works) =====
    run("systemctl stop bulkhead-enforce.service 2>&1"); run("sleep 1 2>/dev/null; true")
    dis = run("bulkhead-collector egress clear self 2>&1; echo RC=$?")
    check("RC=0" in dis, "ARM 7: `systemctl stop bulkhead-enforce` disarmed E0 (routed enforce-off) — the console can bpf() again")

    # ===== ARM 8: audit chains verify (file reads) =====
    v1 = run("bulkhead-collector verify-audit /data/bulkhead/audit/provenance.jsonl 2>&1; echo RC=$?")
    v2 = run("bulkhead-collector verify-audit /data/bulkhead/audit-broker/provenance.jsonl 2>&1; echo RC=$?")
    v3 = run("bulkhead-collector verify-audit /data/bulkhead/audit/control.jsonl 2>&1; echo RC=$?")
    out("\n[verify]\n" + v1 + v2 + v3)
    check(all("verify-audit: OK" in v and "RC=0" in v for v in (v1, v2, v3)),
          "ARM 8: all three signed chains (collector + broker + control) verify after the hardened-boot run")

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
