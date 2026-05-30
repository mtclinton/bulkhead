#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Boot the bulkhead image and verify the default-deny network floor: the
nftables ruleset is loaded with drop policies + the Anthropic allow rule, DNS
and loopback (necessary egress) work, and a forbidden external connection is
blocked. Stdlib only; exits non-zero on failure.
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
TIMEOUT = 240

PROBE = (
    "for i in $(seq 1 30); do systemctl is-active bulkhead-firewall >/dev/null 2>&1 && break; sleep 1; done; "
    "echo '<<<EGRESSSTART'; "
    "echo \"fw-active=$(systemctl is-active bulkhead-firewall)\"; "
    "echo \"drop-policies=$(nft list ruleset 2>/dev/null | grep -c 'policy drop')\"; "
    "echo \"anthropic-rule=$(nft list ruleset 2>/dev/null | grep -c '160.79.104')\"; "
    "echo \"eth0-ip=$(ip -4 -o addr show eth0 2>/dev/null | grep -c 'inet ')\"; "
    "echo \"resolv-ns=$(grep -c '^nameserver' /etc/resolv.conf 2>/dev/null)\"; "
    "(getent hosts example.com >/dev/null 2>&1 && echo dns=ok || echo dns=fail); "
    "(curl -sf -m 5 http://127.0.0.1:8080/health >/dev/null 2>&1 && echo loopback=ok || echo loopback=fail); "
    "curl -s -o /dev/null --connect-timeout 6 -m 8 http://1.1.1.1/; echo \"forbidden-exit=$?\"; "
    "echo \"tailscaled=$(systemctl is-active tailscaled)\"; "
    "echo 'EGRESSEND>>>'; "
    "poweroff\n"
)


def qemu_cmd():
    accel = ["-enable-kvm", "-cpu", "host"] if os.access("/dev/kvm", os.W_OK) else ["-cpu", "max"]
    drives = ["-drive", f"file={ROOTFS},if=virtio,format=raw"]
    if os.path.exists(DATA):
        drives += ["-drive", f"file={DATA},if=virtio,format=raw"]
    return [
        "qemu-system-x86_64", *accel, "-m", "4096", "-smp", "4",
        "-kernel", KERNEL, *drives,
        "-append", CMDLINE,
        "-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0",
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
        if re.search(r"<<<EGRESSSTART\n.*?\nEGRESSEND>>>", "".join(out).replace("\r", ""), re.S):
            break

    try:
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()

    text = "".join(out).replace("\r", "")
    m = re.search(r"<<<EGRESSSTART\n(.*?)\nEGRESSEND>>>", text, re.S)
    if not m:
        print("\n\nFAIL: never captured egress probe output (boot/login timed out)", file=sys.stderr)
        return 1
    body = m.group(1)

    forbidden_blocked = False
    fm = re.search(r"forbidden-exit=(\d+)", body)
    if fm and int(fm.group(1)) != 0:
        forbidden_blocked = True

    checks = [
        ("nftables floor active", "fw-active=active" in body),
        ("input+output drop policies", re.search(r"drop-policies=[2-9]", body) is not None),
        ("Anthropic allow rule present", re.search(r"anthropic-rule=[1-9]", body) is not None),
        ("network up (eth0 has a lease)", "eth0-ip=1" in body),
        ("loopback permitted (router reachable)", "loopback=ok" in body),
        ("forbidden external egress blocked", forbidden_blocked),
    ]
    print("\n\n=== bulkhead egress floor verification ===")
    ok = True
    for name, cond in checks:
        print(("PASS" if cond else "FAIL") + ": " + name)
        ok = ok and cond
    for key in ("eth0-ip", "resolv-ns", "dns", "forbidden-exit", "tailscaled"):
        mm = re.search(rf"{key}=(\S+)", body)
        print(f"note: {key}={mm.group(1) if mm else '?'}")
    print("EGRESS FLOOR OK" if ok else "EGRESS FLOOR INCOMPLETE")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
