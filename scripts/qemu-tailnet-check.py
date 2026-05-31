#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Boot the bulkhead image with the model volume (vdb) and the Tailscale
auth-key provisioning volume (vdc), and verify the node joins the tailnet and
the router rebinds to the tailnet address. Stdlib only; exits non-zero on
failure. (The key volume is built by `make tsauth-disk` from the operator's
~/.bulkhead/tsauthkey and is never committed.)
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
TSAUTH = os.path.join(IMG, "tsauth.ext4")
CMDLINE = "root=/dev/vda rw console=ttyS0 net.ifnames=0 lsm=landlock,lockdown,yama,bpf"
TIMEOUT = 360

PROBE = (
    "for i in $(seq 1 60); do [ -n \"$(tailscale ip -4 2>/dev/null)\" ] && break; sleep 2; done; "
    "echo '<<<TSSTART'; "
    "echo \"ts-up=$(systemctl is-active tailscale-up)\"; "
    "echo \"ts-ip=$(tailscale ip -4 2>/dev/null | head -1)\"; "
    "echo \"ts-backend=$(tailscale status 2>/dev/null | head -1)\"; "
    "echo \"router-env=$(cat /run/bulkhead-router.env 2>/dev/null)\"; "
    "echo \"router=$(systemctl is-active bulkhead-router)\"; "
    "echo 'ts-up-log:'; journalctl -u tailscale-up --no-pager 2>/dev/null | tail -4; "
    "echo 'TSEND>>>'; "
    "poweroff\n"
)


def qemu_cmd():
    accel = ["-enable-kvm", "-cpu", "host"] if os.access("/dev/kvm", os.W_OK) else ["-cpu", "max"]
    return [
        "qemu-system-x86_64", *accel, "-m", "6144", "-smp", "6",
        "-kernel", KERNEL,
        "-drive", f"file={ROOTFS},if=virtio,format=raw",
        "-drive", f"file={DATA},if=virtio,format=raw",
        "-drive", f"file={TSAUTH},if=virtio,format=raw",
        "-append", CMDLINE,
        "-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0",
        "-display", "none", "-serial", "stdio", "-no-reboot",
    ]


def main():
    for f in (KERNEL, ROOTFS, DATA, TSAUTH):
        if not os.path.exists(f):
            print(f"missing {f}; run 'make image', 'make data-disk', 'make tsauth-disk'", file=sys.stderr)
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
        if re.search(r"<<<TSSTART\n.*?\nTSEND>>>", "".join(out).replace("\r", ""), re.S):
            break

    try:
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()

    text = "".join(out).replace("\r", "")
    m = re.search(r"<<<TSSTART\n(.*?)\nTSEND>>>", text, re.S)
    if not m:
        print("\n\nFAIL: never captured tailnet probe output (boot/login/join timed out)", file=sys.stderr)
        return 1
    body = m.group(1)

    checks = [
        ("tailscale-up succeeded", "ts-up=active" in body),
        ("node has a tailnet IP (100.x)", re.search(r"ts-ip=100\.", body) is not None),
        ("router rebound to the tailnet address", re.search(r"router-env=BULKHEAD_LISTEN=100\.", body) is not None),
        ("router running", "router=active" in body),
    ]
    print("\n\n=== bulkhead tailnet-join verification ===")
    ok = True
    for name, cond in checks:
        print(("PASS" if cond else "FAIL") + ": " + name)
        ok = ok and cond
    print("TAILNET JOIN OK" if ok else "TAILNET JOIN INCOMPLETE")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
