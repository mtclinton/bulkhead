#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# ADR-0031 substrate integration, slice 1: prove gVisor/runsc actually RUNS inside the booted
# bulkhead appliance (not just on the dev host where the feasibility spike validated it), and that
# it delivers the load-bearing property — HOST-SURFACE COLLAPSE: a workload run under runsc sees
# gVisor's reimplemented application kernel, NOT the host's 6.x. If a sandboxed `uname -r` reports
# gVisor's 4.4.0 (and dmesg says "Starting gVisor"), the Sentry is interposed and the host syscall
# surface is collapsed to the ~Sentry ABI. We probe a few platform/flag combos and report which one
# works in the appliance, so a blocker (no ptrace/Systrap support) is surfaced explicitly.
# Boots the wic (slirp); stdlib + pexpect. No network, no model needed.
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

    # 0) runsc is installed + is the pinned release.
    ver = run("runsc --version 2>&1")
    check("runsc version" in ver and "release-20260413" in ver, "runsc installed at the pinned release (release-20260413)")
    # Anchor to a version pattern so the regex matches the OUTPUT (6.x.y), not the echoed
    # command "HOSTK=$(uname -r)" the serial console reflects back (the documented serial-echo trap).
    hostk = run("echo HOSTK=$(uname -r)")
    mh = re.search(r"HOSTK=(\d+\.\d+\S*)", hostk); host_kernel = mh.group(1) if mh else "?"
    out(f"\n[host kernel] {host_kernel}\n")

    # 1) Run a workload under runsc and capture the sandboxed kernel. Try platform/flag combos; the
    #    portable target is Systrap (no nested KVM). do uses the host rootfs as the sandbox root.
    combos = [
        ("systrap-root",     "runsc --ignore-cgroups --platform=systrap --network=none do /bin/uname -r"),
        ("systrap-rootless", "runsc --rootless --ignore-cgroups --platform=systrap --network=none do /bin/uname -r"),
        ("kvm-root",         "runsc --ignore-cgroups --platform=kvm --network=none do /bin/uname -r"),
    ]
    sandbox_kernel = None; winning = None
    for name, cmd in combos:
        o = run(f"echo RUNSC_START; {cmd} 2>&1; echo RUNSC_RC=$?", t=120)
        out(f"\n[{name}]\n{o}\n")
        m = re.search(r"RUNSC_START\s+(\d+\.\d+\.\d+\S*)", o)
        rc = re.search(r"RUNSC_RC=(\d+)", o)
        if m and rc and rc.group(1) == "0":
            sandbox_kernel = m.group(1); winning = name
            break

    check(sandbox_kernel is not None, "a workload ran to success under runsc in the appliance")
    out(f"\n[winning platform] {winning}  [sandbox kernel] {sandbox_kernel}\n")
    # HOST-SURFACE COLLAPSE: the sandbox kernel is gVisor's reimplemented kernel, NOT the host's.
    check(sandbox_kernel is not None and sandbox_kernel != host_kernel,
          f"host-surface collapse: the sandboxed kernel ({sandbox_kernel}) differs from the host ({host_kernel})")
    check(sandbox_kernel is not None and sandbox_kernel.startswith("4.4"),
          f"the sandbox reports gVisor's reimplemented kernel (~4.4.x), got {sandbox_kernel}")

    # 2) SLICE 2: the PRODUCTION bulkhead-agent binary runs under the Sentry, and the sandbox enforces
    #    its network isolation. probe-egress under --network=none: KVER confirms it ran under gVisor;
    #    NOROUTE + ISOLATED confirm no direct egress from the sandbox (the substrate's network
    #    isolation applied to the real agent, the same boundary the no-route netns gives today).
    if winning:
        win_flags = dict(combos)[winning].split(" do ")[0]
        # A (dummy) egress sock makes probe-egress run ALL checks, including IOURING: under gVisor,
        # io_uring_setup is ENOSYS (the Sentry doesn't expose io_uring), so ADR-0033's ban comes from
        # the SUBSTRATE itself — no per-jail seccomp filter needed for it.
        ao = run(f"{win_flags} do /bin/sh -c 'echo KVER=$(uname -r); BULKHEAD_EGRESS_SOCK=/nonexistent /usr/bin/bulkhead-agent probe-egress 2>&1'", t=120)
        out(f"\n[bulkhead-agent under runsc]\n{ao}\n")
        check(bool(re.search(r"KVER=4\.4", ao)),
              "the PRODUCTION bulkhead-agent ran UNDER gVisor (sandbox kernel 4.4.x) — Go runtime + net stack are Sentry-compatible")
        check("PROBE NOROUTE: PASS" in ao,
              "agent-under-gVisor: NOROUTE — no direct public egress from the sandbox")
        check("PROBE ISOLATED: PASS" in ao,
              "agent-under-gVisor: ISOLATED — the sandbox loopback is isolated from the host")
        check("PROBE IOURING: PASS" in ao,
              "agent-under-gVisor: IOURING — io_uring_setup denied by the Sentry (ADR-0033's ban from the SUBSTRATE, no seccomp filter)")

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
