#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Boot the bulkhead image in qemu, log in over the serial console, and assert
the kernel security floor is live:

  - BPF-LSM and Landlock present in the active LSM list
  - kernel BTF present (CO-RE prerequisite)
  - cgroup v2 unified hierarchy mounted
  - CONFIG_BPF_LSM / CONFIG_DEBUG_INFO_BTF / CONFIG_CGROUP_BPF /
    CONFIG_SECCOMP_FILTER / CONFIG_SECURITY_LANDLOCK compiled in

Exits non-zero if the floor is incomplete. Stdlib only, so it runs unattended
in CI. This checks that the floor EXISTS; the runtime boot self-test (M5) is the
binding guarantee that it actually DENIES forbidden actions.
"""

import os
import re
import select
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMG = os.path.join(ROOT, "output", "images")
KERNEL = os.path.join(IMG, "bzImage")
ROOTFS = os.path.join(IMG, "rootfs.ext2")
CMDLINE = "root=/dev/vda rw console=ttyS0 net.ifnames=0 lsm=landlock,lockdown,yama,bpf"
TIMEOUT = 180

PROBE = (
    "echo '<<<FLOORSTART'; "
    "cat /sys/kernel/security/lsm; echo; "
    "(test -r /sys/kernel/btf/vmlinux && echo BTF_PRESENT || echo BTF_MISSING); "
    "(test -e /sys/fs/cgroup/cgroup.controllers && echo CGROUP2_PRESENT || echo CGROUP2_MISSING); "
    "zcat /proc/config.gz | grep -E '^CONFIG_(BPF_LSM|DEBUG_INFO_BTF|CGROUP_BPF|SECCOMP_FILTER|SECURITY_LANDLOCK)=y' | sort; "
    "echo 'FLOOREND>>>'; "
    "poweroff\n"
)


def qemu_cmd():
    accel = ["-enable-kvm", "-cpu", "host"] if os.access("/dev/kvm", os.W_OK) else ["-cpu", "max"]
    return [
        "qemu-system-x86_64", *accel, "-m", "2048", "-smp", "2",
        "-kernel", KERNEL,
        "-drive", f"file={ROOTFS},if=virtio,format=raw",
        "-append", CMDLINE,
        "-display", "none", "-serial", "stdio", "-no-reboot",
    ]


def main():
    for f in (KERNEL, ROOTFS):
        if not os.path.exists(f):
            print(f"missing {f}; run 'make image' first", file=sys.stderr)
            return 2

    proc = subprocess.Popen(qemu_cmd(), stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

    def send(s):
        try:
            proc.stdin.write(s.encode())
            proc.stdin.flush()
        except (BrokenPipeError, ValueError):
            pass

    out = []
    logged_in = False
    probed = False
    t_login = 0.0
    deadline = time.time() + TIMEOUT

    while time.time() < deadline and proc.poll() is None:
        r, _, _ = select.select([proc.stdout], [], [], 1.0)
        if r:
            chunk = os.read(proc.stdout.fileno(), 4096)
            if not chunk:
                break
            out.append(chunk.decode(errors="replace"))
            sys.stdout.write(chunk.decode(errors="replace"))
            sys.stdout.flush()
        tail = "".join(out)[-400:].replace("\r", "")

        if not logged_in and re.search(r"login:\s*$", tail):
            send("root\n")
            logged_in = True
            t_login = time.time()
            continue
        if logged_in and tail.endswith("Password: "):
            send("\n")
        if logged_in and not probed and time.time() - t_login > 3:
            send(PROBE)
            probed = True
            continue
        # Break only once the real command OUTPUT is present (marker on its own
        # line), not when the shell merely echoes the typed command.
        if re.search(r"<<<FLOORSTART\n.*?\nFLOOREND>>>", "".join(out).replace("\r", ""), re.S):
            break

    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()

    text = "".join(out).replace("\r", "")
    # Match the command OUTPUT (marker followed by newline), not the shell's echo
    # of the typed command (where the marker is followed by a quote).
    m = re.search(r"<<<FLOORSTART\n(.*?)\nFLOOREND>>>", text, re.S)
    if not m:
        print("\n\nFAIL: never captured floor probe output (boot or login timed out)", file=sys.stderr)
        return 1
    body = m.group(1)

    lsm_names = set()
    for line in body.splitlines():
        if "," in line and "landlock" in line and "bpf" in line:
            lsm_names = {x.strip() for x in line.strip().split(",")}
            break

    checks = [
        ("BPF-LSM active (bpf in lsm list)", "bpf" in lsm_names),
        ("Landlock active (landlock in lsm list)", "landlock" in lsm_names),
        ("kernel BTF present (CO-RE)", "BTF_PRESENT" in body),
        ("cgroup v2 unified hierarchy", "CGROUP2_PRESENT" in body),
        ("CONFIG_BPF_LSM=y", "CONFIG_BPF_LSM=y" in body),
        ("CONFIG_DEBUG_INFO_BTF=y", "CONFIG_DEBUG_INFO_BTF=y" in body),
        ("CONFIG_CGROUP_BPF=y (egress firewall)", "CONFIG_CGROUP_BPF=y" in body),
        ("CONFIG_SECCOMP_FILTER=y", "CONFIG_SECCOMP_FILTER=y" in body),
        ("CONFIG_SECURITY_LANDLOCK=y", "CONFIG_SECURITY_LANDLOCK=y" in body),
    ]

    print("\n\n=== bulkhead floor verification ===")
    ok = True
    for name, cond in checks:
        print(("PASS" if cond else "FAIL") + ": " + name)
        ok = ok and cond
    print("FLOOR OK" if ok else "FLOOR INCOMPLETE")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
