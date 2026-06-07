#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Verify the E2 egress-class gate (classify_dest) LIVE, with a focus on the IPv4-mapped-IPv6
# bypass closed by the b022155 fix: an AF_INET6 connect() to ::ffff:169.254.169.254 (cloud
# metadata) / ::ffff:127.0.0.1 (loopback) / v4-mapped RFC1918 must be classified by its embedded
# IPv4 (LINKLOCAL/LOOPBACK/PRIVATE), NOT fall through to DST_PUBLIC. Before the fix those slipped
# the per-class manifest as PUBLIC; this asserts they are now DENIED.
#
# Method (all from the console's OWN non-TCB cgroup — children inherit it, so a `probe connect6`
# child is gated by the manifest we set on the console):
#   1. Disarm the boot-armed E0/E2 (ADR-0018) to reach OBSERVE, where a non-TCB bpf() write works.
#   2. `egress set self public,other` — grant PUBLIC + OTHER (AF_UNIX, so systemctl/journalctl/
#      control-socket ops keep working) but DENY loopback/linklocal/private — the discriminators.
#   3. Arm E2 ONLY (`bulkhead-enforce-egress`); leave E0 in observe.
#   4. probe connect6 (genuine AF_INET6, raw syscall — no getaddrinfo normalization):
#        ::ffff:169.254.169.254  -> DENIED (LINKLOCAL not granted)   [the headline; ALLOWED pre-fix]
#        ::ffff:127.0.0.1        -> DENIED (LOOPBACK not granted)     [v4-mapped loopback]
#        ::1                     -> DENIED (LOOPBACK not granted)     [native ::1 regression guard]
#        ::ffff:8.8.8.8          -> ALLOWED (PUBLIC granted)          [CONTROL: proves the manifest
#                                   actually grants — guards against a meaningless all-deny pass,
#                                   and proves the metadata DENY is reclassification, not blanket]
# On the buggy (pre-b022155) object the metadata + v4-mapped-loopback probes classify as DST_PUBLIC,
# which IS granted, so they return ALLOWED and this harness FAILS — i.e. it is a failing-then-passing
# test for the fix. Stdlib + pexpect only.
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
    def probe(addr, port=80):
        o = run(f"bulkhead-collector probe connect6 {addr} {port} 2>&1; echo RC=$?")
        denied = ("DENIED" in o) and bool(re.search(r"RC=1\b", o))
        allowed = ("ALLOWED by E2" in o) and bool(re.search(r"RC=0\b", o))
        return denied, allowed, o

    check("active" in run("systemctl is-active bulkhead-collector 2>&1"), "collector active")

    # 1. Disarm the boot-armed E0+E2 to reach observe (the routed `systemctl stop` works even under
    #    armed E0 — enforce-off goes through the collector/TCB).
    run("systemctl stop bulkhead-enforce.service bulkhead-enforce-egress.service 2>&1")
    run("sleep 1 2>/dev/null; true")

    # 2. Manifest on the console's own cgroup: PUBLIC + OTHER, NOT loopback/linklocal/private.
    setm = run("bulkhead-collector egress set self public,other 2>&1; echo RC=$?")
    out("\n[egress set self public,other]\n" + setm)
    st = run("bulkhead-collector status 2>&1 | sed -n '/egress manifests/,$p'")
    out("\n[status: manifests]\n" + st)
    check("RC=0" in setm and "public" in st and "other" in st and "linklocal" not in st and "loopback" not in st,
          "manifest set on the console cgroup = public,other (loopback/linklocal/private DENIED)")

    # 3. Arm E2 only (connect enforce); E0 stays in observe.
    run("systemctl start bulkhead-enforce-egress.service 2>&1"); run("sleep 1 2>/dev/null; true")
    e2 = run("systemctl is-active bulkhead-enforce-egress.service 2>&1")
    check("active" in e2, "E2 (egress connect enforce) armed; E0 left in observe")

    # 4a. CONTROL FIRST: a v4-mapped PUBLIC dest must be ALLOWED — proves the manifest actually
    #     grants PUBLIC, so a subsequent DENY can only be reclassification (not a blanket deny).
    d, a, o = probe("::ffff:8.8.8.8"); out("\n[probe ::ffff:8.8.8.8 (PUBLIC, control)]\n" + o)
    check(a and not d, "CONTROL: ::ffff:8.8.8.8 ALLOWED (v4-mapped PUBLIC is granted — manifest is live, not all-deny)")

    # 4b. HEADLINE: v4-mapped cloud-metadata must now be DENIED (classified LINKLOCAL, not PUBLIC).
    d, a, o = probe("::ffff:169.254.169.254"); out("\n[probe ::ffff:169.254.169.254 (metadata)]\n" + o)
    check(d and not a,
          "HEADLINE: ::ffff:169.254.169.254 DENIED — v4-mapped link-local no longer slips as DST_PUBLIC (the fix)")

    # 4c. v4-mapped loopback DENIED (classified LOOPBACK).
    d, a, o = probe("::ffff:127.0.0.1"); out("\n[probe ::ffff:127.0.0.1 (v4-mapped loopback)]\n" + o)
    check(d and not a, "::ffff:127.0.0.1 DENIED — v4-mapped loopback classified LOOPBACK, not PUBLIC")

    # 4d. native ::1 loopback DENIED (regression guard on the pre-existing ::1 path).
    d, a, o = probe("::1"); out("\n[probe ::1 (native loopback)]\n" + o)
    check(d and not a, "::1 DENIED — native IPv6 loopback still classified LOOPBACK (no regression)")

    # cleanup
    run("systemctl stop bulkhead-enforce-egress.service 2>&1")
    run("bulkhead-collector egress clear self 2>&1")
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
