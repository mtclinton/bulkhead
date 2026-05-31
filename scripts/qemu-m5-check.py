#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Boot the bulkhead image (with the model data disk) and verify M5: the
fail-closed self-test passed (so the gated services started), the eBPF collector
attached its BPF-LSM program, and the hash-chained signed audit log is being
written. Stdlib only; exits non-zero on failure.
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
DATA = os.path.join(IMG, "data.ext4")
CMDLINE = "root=/dev/vda rw console=ttyS0 net.ifnames=0 lsm=landlock,lockdown,yama,bpf"
TIMEOUT = 300
AUDIT = "/var/lib/bulkhead/audit/provenance.jsonl"

PROBE = (
    "for i in $(seq 1 40); do systemctl is-active bulkhead-collector >/dev/null 2>&1 && break; sleep 2; done; "
    "echo '<<<M5START'; "
    "echo \"selftest=$(systemctl is-active bulkhead-selftest)\"; "
    "echo \"collector=$(systemctl is-active bulkhead-collector)\"; "
    "echo \"llama=$(systemctl is-active llama-server)\"; "
    "echo \"router=$(systemctl is-active bulkhead-router)\"; "
    "curl -s -m 3 http://127.0.0.1:8080/health >/dev/null 2>&1; sleep 1; "
    f"echo \"audit-lines=$(wc -l < {AUDIT} 2>/dev/null || echo 0)\"; "
    f"echo \"audit-signed=$(tail -n1 {AUDIT} 2>/dev/null | grep -c '\"sig\"')\"; "
    "echo \"attached=$(journalctl -u bulkhead-collector --no-pager 2>/dev/null | grep -c 'BPF-LSM attached')\"; "
    "echo 'M5END>>>'; "
    "poweroff\n"
)


def qemu_cmd():
    accel = ["-enable-kvm", "-cpu", "host"] if os.access("/dev/kvm", os.W_OK) else ["-cpu", "max"]
    return [
        "qemu-system-x86_64", *accel, "-m", "6144", "-smp", "6",
        "-kernel", KERNEL,
        "-drive", f"file={ROOTFS},if=virtio,format=raw",
        "-drive", f"file={DATA},if=virtio,format=raw",
        "-append", CMDLINE,
        "-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0",
        "-display", "none", "-serial", "stdio", "-no-reboot",
    ]


def main():
    for f in (KERNEL, ROOTFS, DATA):
        if not os.path.exists(f):
            print(f"missing {f}; run 'make image' and 'make data-disk' first", file=sys.stderr)
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
    logged_in = probed = False
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
        if re.search(r"<<<M5START\n.*?\nM5END>>>", "".join(out).replace("\r", ""), re.S):
            break

    try:
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()

    text = "".join(out).replace("\r", "")
    m = re.search(r"<<<M5START\n(.*?)\nM5END>>>", text, re.S)
    if not m:
        print("\n\nFAIL: never captured M5 probe output (boot/login timed out)", file=sys.stderr)
        return 1
    body = m.group(1)

    checks = [
        ("self-test passed (oneshot active)", "selftest=active" in body),
        ("collector running", "collector=active" in body),
        ("gated llama-server started", "llama=active" in body),
        ("gated router started", "router=active" in body),
        ("BPF-LSM program attached", re.search(r"attached=[1-9]", body) is not None),
        ("audit log has records", re.search(r"audit-lines=[1-9]", body) is not None),
        ("audit records are signed", re.search(r"audit-signed=[1-9]", body) is not None),
    ]
    print("\n\n=== bulkhead M5 (provenance + self-test) verification ===")
    ok = True
    for name, cond in checks:
        print(("PASS" if cond else "FAIL") + ": " + name)
        ok = ok and cond
    print("M5 OK" if ok else "M5 INCOMPLETE")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
