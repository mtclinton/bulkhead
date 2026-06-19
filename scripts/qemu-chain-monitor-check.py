#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
#
# LIVE end-to-end arm for the off-box audit-chain monitor (bulkhead-chain-monitor) — the
# PRODUCTION-READINESS "continuous off-box monitor" pilot blocker. The monitor's underlying primitives are
# ALREADY live-proven on the real appliance by qemu-attest-check.py (a fresh-nonce quote binds the chain
# HEADs; `verify-audit --expect-tip` ties the quote HEAD to the verified log; `--since=<bogus>` is rejected
# as REWOUND), and the monitor's pin/advance/rewind/missed orchestration is unit-proven. This arm proves the
# monitor BINARY end-to-end against a booted appliance:
#   POLL 1: the monitor pulls a fresh-nonce quote over a live bridge to the box, verifies it (host
#           bulkhead-collector, box AK pin + box-reported D), and pins the control-chain HEAD -> GREEN.
#   TRUNCATE: drop the control chain's last record on the box (a withheld/rewound tail).
#   POLL 2: a fresh quote now binds the truncated tip; the monitor's verify-audit --since=<pinned>
#           --expect-tip=<new> fails closed -> the monitor ALERTS (chain-rewind-or-fail), exit 1.
#
# The monitor runs ON THE HOST and reaches the box through a guest-exec UNIX-socket bridge (the appliance's
# real transport is ssh-over-tailnet; the bridge stands in for it here so the monitor's OWN fresh nonce
# flows to the box per poll). Needs a built wic + swtpm (run-qemu-tpm.sh) + a host Go toolchain.
import pexpect, sys, os, re, secrets, socket, threading, subprocess, tempfile, json, time, base64

REPO = "/home/work/ideas/bulkhead"
RUN = f"{REPO}/yocto/scripts/run-qemu-tpm.sh"
CTLCHAIN = "/data/bulkhead/audit/control.jsonl"
PS = "BHX_PROMPT> "
results = {}
def out(s): sys.stdout.write(s); sys.stdout.flush()
def check(c, l): results[l] = bool(c); out(f"\n[CHECK] {'PASS' if c else 'FAIL'}: {l}\n")

# --- build the host binaries (the relying-party verifier + the monitor) ---
work = tempfile.mkdtemp(prefix="chain-mon-live-")
COLLECTOR = os.path.join(work, "bulkhead-collector")
MONITOR = os.path.join(work, "bulkhead-chain-monitor")
def build(mod, outp):
    subprocess.run(["go", "build", "-o", outp, "."], cwd=f"{REPO}/src/{mod}",
                   env={**os.environ, "CGO_ENABLED": "0"}, check=True)
build("collector", COLLECTOR)
build("chain-monitor", MONITOR)
out(f"[built host bulkhead-collector + bulkhead-chain-monitor in {work}]\n")

child = None
bridge_sock = os.path.join(work, "guest-exec.sock")
run_lock = threading.Lock()
stop = threading.Event()

try:
    child = pexpect.spawn("/bin/bash", ["-c", f"exec bash {RUN}"], timeout=300, encoding="utf-8", codec_errors="replace")
    child.logfile_read = sys.stdout
    child.expect("login:", timeout=360); child.sendline("root")
    i = child.expect(["Password:", r"@qemux86-64:~#"], timeout=60)
    if i == 0: child.sendline(""); child.expect(r"@qemux86-64:~#", timeout=30)
    child.sendline(f"export PS1='{PS}'"); child.expect(PS, timeout=30); child.expect(PS, timeout=30)
    child.sendline("stty cols 8000 2>/dev/null; true"); child.expect(PS, timeout=30)  # don't wrap the command echo

    # run a guest command, return (stdout, rc). Markers are line-anchored so the command ECHO (which contains
    # the literal marker mid-line) is not mistaken for the output marker (qemu serial interleaves echoes).
    def guest(cmd, t=90):
        # Capture RAW program output between line-anchored markers. Program output to the serial console is
        # NOT readline-wrapped (only the command ECHO is, which we skip by matching BARE-line markers — the
        # echo has the markers mid-line). The TTY is widened (stty cols, below) so even the long quote-JSON
        # line is not wrapped. `r=$?` captures the COMMAND's rc, not the trailing separator echo's.
        with run_lock:
            child.sendline(f"echo BHMQS; {cmd}; r=$?; echo; echo BHMQE$r")
            child.expect(PS, timeout=t)
            b = child.before
        payload, rc, collecting = [], 1, False
        for ln in b.replace("\r", "").split("\n"):
            if not collecting:
                if ln.strip() == "BHMQS":
                    collecting = True
                continue
            m = re.match(r"BHMQE(\d+)$", ln.strip())
            if m:
                rc = int(m.group(1)); break
            payload.append(ln)
        while payload and payload[-1].strip() == "":  # drop the trailing separator echo
            payload.pop()
        return ("\n".join(payload), rc)

    def is_active(u): return guest(f"systemctl is-active {u} >/dev/null 2>&1")[1] == 0
    check(is_active("bulkhead-collector.service"), "collector active")
    check(is_active("bulkhead-enforce.service") and is_active("bulkhead-enforce-egress.service"),
          "E0 + E2 armed from cold boot (the enforcing posture being attested)")

    # capture the box-reported expected-D + the control chain's audit pubkey (the monitor verifies with
    # these — D is public; the pub resolves the chain signature off-box where the sibling audit-pub.txt
    # is not shipped alongside the fetched log).
    dx, _ = guest("bulkhead-collector attest expected-d /usr/bin/bulkhead-collector")
    mD = re.search(r"\b([0-9a-f]{64})\b", dx)
    D = mD.group(1) if mD else ""
    pub, _ = guest("cat /data/bulkhead/audit/audit-pub.txt")
    pub = pub.strip()
    pubfile = os.path.join(work, "audit-pub.txt"); open(pubfile, "w").write(pub)
    check(len(D) == 64 and re.fullmatch(r"[0-9a-f]+", pub or "") is not None,
          "captured box-reported expected-D + control-chain audit pubkey")

    # how many records in the control chain (need >=2 so truncation leaves a valid shorter chain).
    nrec, _ = guest(f"wc -l < {CTLCHAIN}")
    nrec = int((nrec.strip() or "0"))
    check(nrec >= 2, f"control chain has >=2 records ({nrec}) so a tail-truncation is testable")

    # --- the guest-exec bridge: a UNIX socket the monitor's transport dials; we run the line in-guest. ---
    def serve():
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(bridge_sock); srv.listen(8); srv.settimeout(1.0)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            data = b""
            while not data.endswith(b"\n"):
                chunk = conn.recv(4096)
                if not chunk: break
                data += chunk
            cmd = data.decode().strip()
            sout, rc = guest(cmd) if cmd else ("", 1)
            conn.sendall((str(rc) + "\n").encode() + sout.encode())
            conn.close()
        srv.close()
    t = threading.Thread(target=serve, daemon=True); t.start()

    # the monitor's transport command = a tiny client that dials the bridge with the (nonce/chain)-substituted line.
    client = os.path.join(work, "gx.py")
    open(client, "w").write(
        "import socket,sys\n"
        f"s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect({bridge_sock!r})\n"
        "s.sendall((sys.argv[1]+'\\n').encode()); d=b''\n"
        "while True:\n c=s.recv(4096)\n if not c: break\n d+=c\n"
        "rc,_,body=d.partition(b'\\n'); sys.stdout.buffer.write(body); sys.exit(int(rc or 1))\n")

    state_dir = os.path.join(work, "state")
    cfg = {
        "interval_seconds": 1, "missed_threshold": 2, "state_dir": state_dir, "collector_bin": COLLECTOR,
        "devices": [{
            "name": "qemu-box", "expected_d": D, "audit_pub": "@" + pubfile,
            "quote_cmd": f"python3 {client} 'bulkhead-collector attest quote {{nonce}}'",
            "fetch_chain_cmd": f"python3 {client} 'cat {{chain}}'",
            "chains": [{"domain": "control", "remote_path": CTLCHAIN, "head_field": "head_control_hex"}],
        }],
    }
    cfgfile = os.path.join(work, "cfg.json"); open(cfgfile, "w").write(json.dumps(cfg))

    def monitor_once():
        p = subprocess.run([MONITOR, "-config", cfgfile, "-once"], capture_output=True, text=True)
        out("\n[monitor]\n" + p.stdout + p.stderr + f"\n[exit {p.returncode}]\n")
        return p.returncode, p.stdout + p.stderr

    # POLL 1 — fresh nonce, live quote, verify, pin the control HEAD. Expect GREEN (exit 0).
    rc1, o1 = monitor_once()
    pinned = ""
    sf = os.path.join(state_dir, "device-qemu-box.json")
    if os.path.exists(sf):
        pinned = json.load(open(sf)).get("chains", {}).get("control", {}).get("pinned_head_hex", "")
    check(rc1 == 0 and "OK device=qemu-box" in o1 and re.fullmatch(r"[0-9a-f]{64}", pinned or "") is not None,
          f"POLL 1 GREEN: monitor verified a fresh-nonce quote off-box + pinned the control HEAD ({pinned[:16]}…)")

    # TRUNCATE the control chain's tail on the box (drop the last record): a withheld/rewound tail.
    _, trc = guest(f"sed '$d' {CTLCHAIN} > {CTLCHAIN}.t && cat {CTLCHAIN}.t > {CTLCHAIN} && rm -f {CTLCHAIN}.t; echo OK")
    nrec2, _ = guest(f"wc -l < {CTLCHAIN}"); nrec2 = int((nrec2.strip() or "0"))
    check(nrec2 == nrec - 1, f"truncated the control chain tail on the box ({nrec} -> {nrec2} records)")

    # POLL 2 — a fresh quote now binds the truncated tip; the prior-pinned HEAD is no longer an ancestor.
    # Expect the monitor to ALERT (chain-rewind-or-fail) and exit nonzero — within one interval.
    rc2, o2 = monitor_once()
    check(rc2 != 0 and "ALERT" in o2 and "chain-rewind-or-fail" in o2 and "control" in o2,
          "POLL 2 ALERT: the monitor detected the truncated tail off-box (prior-pinned HEAD no longer a verified ancestor) and fired chain-rewind-or-fail")

    # the rewound chain must NOT advance the pin (keep the last-good anchor).
    pinned2 = json.load(open(sf)).get("chains", {}).get("control", {}).get("pinned_head_hex", "") if os.path.exists(sf) else ""
    check(pinned2 == pinned, "monitor kept the last-good HEAD anchor (did not advance the pin on a rewind)")

    out("\n=== off-box chain monitor LIVE: %d passed, %d failed ===\n" %
        (sum(1 for v in results.values() if v), sum(1 for v in results.values() if not v)))
    print("CHAIN MONITOR LIVE GO" if all(results.values()) else "CHAIN MONITOR LIVE INCOMPLETE")
    sys.exit(0 if all(results.values()) else 1)

finally:
    stop.set()
    try:
        if child and child.isalive():
            child.sendline("poweroff -f 2>/dev/null || poweroff"); time.sleep(2); child.close(force=True)
    except Exception:
        pass
