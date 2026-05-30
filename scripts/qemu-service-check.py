#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Boot the bulkhead image in qemu with the model data disk attached, then assert
the local inference service is healthy: llama-server.service active, /health OK,
and a chat completion returns content. Stdlib only; exits non-zero on failure.
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

PROBE = (
    "for i in $(seq 1 40); do curl -sf -m 5 http://127.0.0.1:8081/health >/dev/null 2>&1 && break; sleep 2; done; "
    "echo '<<<SVCSTART'; "
    "echo -n 'is-active='; systemctl is-active llama-server; "
    "echo -n 'health='; curl -s -m 10 http://127.0.0.1:8081/health; echo; "
    "echo -n 'completion='; curl -s -m 120 http://127.0.0.1:8081/v1/chat/completions "
    "-H 'content-type: application/json' "
    "-d '{\"messages\":[{\"role\":\"user\",\"content\":\"Reply with one word: pong\"}],\"max_tokens\":16}'; echo; "
    "echo 'SVCEND>>>'; "
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
        if re.search(r"<<<SVCSTART\n.*?\nSVCEND>>>", "".join(out).replace("\r", ""), re.S):
            break

    try:
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()

    text = "".join(out).replace("\r", "")
    m = re.search(r"<<<SVCSTART\n(.*?)\nSVCEND>>>", text, re.S)
    if not m:
        print("\n\nFAIL: never captured service probe output (boot/login/model-load timed out)", file=sys.stderr)
        return 1
    body = m.group(1)

    active = re.search(r"is-active=active", body) is not None
    health_ok = '"status"' in body and "ok" in body.lower()
    completion_ok = bool(re.search(r'completion=.*"content"\s*:\s*"[^"]', body, re.S))

    print("\n\n=== bulkhead local inference verification ===")
    ok = True
    for name, cond in [
        ("llama-server.service active", active),
        ("/health responds OK", health_ok),
        ("chat completion returns content", completion_ok),
    ]:
        print(("PASS" if cond else "FAIL") + ": " + name)
        ok = ok and cond
    print("INFERENCE OK" if ok else "INFERENCE INCOMPLETE")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
