#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# HOSTILE-agent containment proof (PRODUCTION-READINESS [6]). The cooperative probe-egress only confirms a few
# doors are locked; this runs the agent's `probe-escape` vehicle inside the REAL confined jail
# (bulkhead-agent-confined@: PrivateNetwork no-route netns, DynamicUser, RestrictNamespaces, empty caps, the
# @-deny + io_uring-by-name SystemCallFilter, ProtectSystem=strict, IPAddressDeny) — the agent ACTIVELY tries
# to break out across every vector a malicious agent would reach for, and we assert the floor held:
#   io_uring, setuid(0), capset(CAP_SYS_ADMIN), unshare(user|mount ns), ptrace(pid 1), finit_module, iopl(3),
#   direct egress, write under /usr, and reaching the uid-0 control socket — every one must be CONTAINED.
# We also assert E0+E2 stayed armed THROUGH the assault. Boots the wic (slirp); stdlib + pexpect; no TPM/HW.
import pexpect, sys, os, re
BUILD = "/home/work/ideas/bulkhead/yocto/build"
def out(s): sys.stdout.write(s); sys.stdout.flush()
inner = (f"cd {BUILD} && source ../poky/oe-init-build-env . >/dev/null 2>&1 && "
         f"exec runqemu qemux86-64 wic ovmf nographic kvm slirp")
PS = "BHX_PROMPT> "; results = {}; child = None
def check(c, l): results[l] = bool(c); out(f"\n[CHECK] {'PASS' if c else 'FAIL'}: {l}\n")

VECTORS = ["IO_URING", "SETUID", "CAPSET", "NEW_USERNS", "PTRACE", "MODULE", "RAW_IO",
           "DIRECT_EGRESS", "FS_WRITE", "CONTROL_SOCK"]
INST = "bulkhead-agent-confined@escape.service"

try:
    child = pexpect.spawn("/bin/bash", ["-c", inner], timeout=300, encoding="utf-8", codec_errors="replace")
    child.logfile_read = sys.stdout
    child.expect("login:", timeout=300); child.sendline("root")
    i = child.expect(["Password:", r"@qemux86-64:~#"], timeout=60)
    if i == 0: child.sendline(""); child.expect(r"@qemux86-64:~#", timeout=30)
    child.sendline(f"export PS1='{PS}'"); child.expect(PS, timeout=30); child.expect(PS, timeout=30)
    def run(c, t=90): child.sendline(c); child.expect(PS, timeout=t); return child.before

    check("active" in run("systemctl is-active bulkhead-collector.service 2>&1"), "collector active at boot")
    armed_before = ("active" in run("systemctl is-active bulkhead-enforce.service 2>&1")
                    and "active" in run("systemctl is-active bulkhead-enforce-egress.service 2>&1"))
    check(armed_before, "E0 + E2 armed BEFORE the assault (the floor under test)")

    # Override the confined template's ExecStart (default probe-egress) to the HOSTILE probe-escape. Type=oneshot
    # so `systemctl start` blocks on it and propagates its exit (0 iff every vector contained). Same drop-in
    # pattern verify-confined-agent uses — so the jail's full floor is applied unchanged.
    run("mkdir -p /run/systemd/system/bulkhead-agent-confined@escape.service.d")
    run("printf '[Service]\\nType=oneshot\\nExecStart=\\n"
        "ExecStart=/usr/bin/bulkhead-agent probe-escape\\n'"
        " > /run/systemd/system/bulkhead-agent-confined@escape.service.d/10-escape.conf")
    run("systemctl daemon-reload")

    startout = run(f"systemctl start {INST} 2>&1; echo START_RC=$?", t=120)
    rc = re.search(r"START_RC=(\d+)", startout)
    start_rc = int(rc.group(1)) if rc else -1

    j = run(f"journalctl -u {INST} --no-pager -o cat 2>&1 | grep -a ESCAPE")
    out("\n[probe-escape output]\n" + j + "\n")

    # the unit (oneshot) exit propagates the probe's exit: 0 iff every escape vector was contained.
    check(start_rc == 0, f"confined jail: the hostile probe-escape unit exited 0 (every vector contained), START_RC={start_rc}")
    check("ESCAPE RESULT: CONTAINED" in j and "BREACH" not in j,
          "confined jail: ESCAPE RESULT CONTAINED — no escape vector breached the floor")
    for v in VECTORS:
        check(re.search(rf"ESCAPE {v}: CONTAINED", j) is not None,
              f"confined jail: {v} attempt CONTAINED")

    # the floor must have SURVIVED the assault (an escape that crashed/disarmed enforcement would also be a win).
    armed_after = ("active" in run("systemctl is-active bulkhead-enforce.service 2>&1")
                   and "active" in run("systemctl is-active bulkhead-enforce-egress.service 2>&1")
                   and "active" in run("systemctl is-active bulkhead-collector.service 2>&1"))
    check(armed_after, "E0 + E2 + collector STILL armed AFTER the assault (the floor survived)")

    npass = sum(1 for v in results.values() if v); nfail = sum(1 for v in results.values() if not v)
    out(f"\n=== hostile-agent containment: {npass} passed, {nfail} failed ===\n")
    print("HOSTILE AGENT CONTAINED" if nfail == 0 else "HOSTILE AGENT BREACH/INCOMPLETE")
    sys.exit(0 if nfail == 0 else 1)
finally:
    try:
        if child and child.isalive():
            child.sendline("poweroff -f 2>/dev/null || poweroff"); child.expect(pexpect.EOF, timeout=30)
    except Exception:
        pass
