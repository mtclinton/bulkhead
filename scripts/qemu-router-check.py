#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Boot the bulkhead image (with the model data volume) and verify the router:
the bulkhead-router service is active; a short prompt routes to the LOCAL tier
and returns a completion; a long prompt routes to the API tier (and returns 503
without a key, proving the routing decision and the no-key handling); and the
AGPL section 13 /source endpoint + X-Source-Code header are served. Stdlib only.
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
    "for i in $(seq 1 40); do curl -sf -m 5 http://127.0.0.1:8080/health >/dev/null 2>&1 && "
    "curl -sf -m 5 http://127.0.0.1:8081/health >/dev/null 2>&1 && break; sleep 2; done; "
    "echo '<<<ROUTERSTART'; "
    "echo \"router-active=$(systemctl is-active bulkhead-router)\"; "
    "curl -s -m 120 -o /tmp/lb "
    "-w 'local route=%header{x-bulkhead-route} status=%{http_code} src=%header{x-source-code}\\n' "
    "http://127.0.0.1:8080/v1/chat/completions -H 'content-type: application/json' "
    "-d '{\"messages\":[{\"role\":\"user\",\"content\":\"Reply with one word: pong\"}],\"max_tokens\":16}'; "
    "echo \"local-content=$(grep -c content /tmp/lb)\"; "
    "LONG=$(yes x | head -n 2300 | tr -d '\\n'); "
    "curl -s -m 30 -o /dev/null "
    "-w 'api route=%header{x-bulkhead-route} status=%{http_code}\\n' "
    "http://127.0.0.1:8080/v1/chat/completions -H 'content-type: application/json' "
    "-d \"{\\\"messages\\\":[{\\\"role\\\":\\\"user\\\",\\\"content\\\":\\\"$LONG\\\"}],\\\"max_tokens\\\":16}\"; "
    "curl -s -m 5 -o /dev/null -w 'source status=%{http_code}\\n' http://127.0.0.1:8080/source; "
    "echo 'ROUTEREND>>>'; "
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
        if re.search(r"<<<ROUTERSTART\n.*?\nROUTEREND>>>", "".join(out).replace("\r", ""), re.S):
            break

    try:
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()

    text = "".join(out).replace("\r", "")
    m = re.search(r"<<<ROUTERSTART\n(.*?)\nROUTEREND>>>", text, re.S)
    if not m:
        print("\n\nFAIL: never captured router probe output (boot/login/model-load timed out)", file=sys.stderr)
        return 1
    body = m.group(1)

    checks = [
        ("bulkhead-router.service active", "router-active=active" in body),
        ("short prompt routes local", re.search(r"local route=local status=200", body) is not None),
        ("local route returns a completion", re.search(r"local-content=[1-9]", body) is not None),
        ("X-Source-Code header served (AGPL 13)", "src=https://github.com/mtclinton/bulkhead" in body),
        ("long prompt routes api", re.search(r"api route=api", body) is not None),
        ("api route 503 without key", re.search(r"api route=api status=503", body) is not None),
        ("/source redirects (302)", "source status=302" in body),
    ]
    print("\n\n=== bulkhead router verification ===")
    ok = True
    for name, cond in checks:
        print(("PASS" if cond else "FAIL") + ": " + name)
        ok = ok and cond
    print("ROUTER OK" if ok else "ROUTER INCOMPLETE")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
