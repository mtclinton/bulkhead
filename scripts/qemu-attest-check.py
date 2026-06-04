#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Verify ADR-0019 remote attestation LIVE under a software TPM (swtpm via run-qemu-tpm.sh): the
# collector measures its own enforcing TCB into a TPM PCR at boot and, on a fresh verifier NONCE,
# produces an AK-signed quote an OFF-BOX verifier checks — so a relying party can cryptographically
# PROVE the box is in the expected ENFORCING state before trusting it.
#
# PROOFS: (1) the hardened image boots E0+E2 armed (the precondition — attestation is meaningful only
# on an enforcing box) and bulkhead-attest.service ran the boot `attest extend` (routed through the
# collector, TCB, so its bpf() map reads survive armed-E0); (2) `attest quote <nonce>` returns a
# genuine TPM quote; (3) `attest verify` PASSES against the measured digest + the fresh nonce;
# (4) NEGATIVE — verify FAILS CLOSED against a TAMPERED expected digest (a box in a different state
# than expected cannot pass); (5) NEGATIVE — verify FAILS against a DIFFERENT nonce (no replay).
import pexpect, sys, os, re, secrets
RUN = "/home/work/ideas/bulkhead/yocto/scripts/run-qemu-tpm.sh"
def out(s): sys.stdout.write(s); sys.stdout.flush()
PS = "BHX_PROMPT> "; results = {}; child = None
def check(c, l): results[l] = bool(c); out(f"\n[CHECK] {'PASS' if c else 'FAIL'}: {l}\n")
try:
    child = pexpect.spawn("/bin/bash", ["-c", f"exec bash {RUN}"], timeout=300, encoding="utf-8", codec_errors="replace")
    child.logfile_read = sys.stdout
    child.expect("login:", timeout=360); child.sendline("root")
    i = child.expect(["Password:", r"@qemux86-64:~#"], timeout=60)
    if i == 0: child.sendline(""); child.expect(r"@qemux86-64:~#", timeout=30)
    child.sendline(f"export PS1='{PS}'"); child.expect(PS, timeout=30); child.expect(PS, timeout=30)
    def run(c, t=90): child.sendline(c); child.expect(PS, timeout=t); return child.before
    def is_active(u): return "RC=0" in run(f"systemctl is-active {u} >/dev/null 2>&1; echo RC=$?")

    check(is_active("bulkhead-collector.service"), "collector active")
    check("RC=0" in run("test -c /dev/tpmrm0; echo RC=$?"), "/dev/tpmrm0 present (TPM attached via swtpm)")
    # precondition: the hardened image booted E0+E2 armed (ADR-0018) — attestation proves an ENFORCING box.
    check(is_active("bulkhead-enforce.service") and is_active("bulkhead-enforce-egress.service"),
          "E0 + E2 armed from cold boot (the enforcing posture being attested)")
    # the boot extend ran (routed through the collector, TCB) and logged the measured digest.
    for _ in range(15):
        if not is_active("bulkhead-attest.service"): run("sleep 2 2>/dev/null; true")
        else: break
    aj = run("journalctl -u bulkhead-attest.service --no-pager 2>&1 | grep -a 'attest:' | tail -3")
    out("\n[attest boot journal]\n" + aj + "\n")
    m = re.search(r"TCB digest ([0-9a-f]{64})", aj)
    D = m.group(1) if m else ""
    check(is_active("bulkhead-attest.service") and D != "",
          "bulkhead-attest.service extended the TCB digest into the PCR at boot (post-arm, via the collector)")

    # quote under a FRESH verifier nonce -> envelope written directly to a guest file.
    nonce = secrets.token_hex(32)
    q = run(f"bulkhead-collector attest quote {nonce} > /tmp/env.json 2>/tmp/env.err; echo RC=$?")
    err = run("cat /tmp/env.err 2>&1")
    out("\n[quote err]\n" + err + "\n")
    check("RC=0" in q and "magic" not in err.lower(),
          "attest quote <nonce> produced a TPM quote envelope (collector did the TPM2_Quote in-process)")

    # POSITIVE verify: genuine quote, fresh nonce, AK sig, PCR == H(0^32 || measured-D).
    v = run(f"bulkhead-collector attest verify /tmp/env.json {D} {nonce} 2>&1; echo RC=$?")
    out("\n[verify+]\n" + v + "\n")
    check("attest verify: OK" in v and "RC=0" in v,
          "attest verify OK — a relying party can PROVE the enforcing-TCB state (genuine quote + fresh nonce + AK sig + PCR match)")

    # NEGATIVE 1 — TAMPER: a different expected digest (one byte flipped) must FAIL CLOSED.
    badD = ("0" if D[0] != "0" else "1") + D[1:]
    v2 = run(f"bulkhead-collector attest verify /tmp/env.json {badD} {nonce} 2>&1; echo RC=$?")
    out("\n[verify- tamper]\n" + v2 + "\n")
    check("RC=0" not in v2 and "FAIL" in v2,
          "tamper rejected: verify FAILS CLOSED against a different expected digest (a box not in the expected state cannot pass)")

    # NEGATIVE 2 — REPLAY: a different nonce than the quote was bound to must FAIL.
    other = secrets.token_hex(32)
    v3 = run(f"bulkhead-collector attest verify /tmp/env.json {D} {other} 2>&1; echo RC=$?")
    out("\n[verify- replay]\n" + v3 + "\n")
    check("RC=0" not in v3 and "FAIL" in v3,
          "replay rejected: verify FAILS against a nonce the quote was not bound to (no stale-quote replay)")

    run("poweroff", t=20)
except Exception as e:
    out(f"\n[harness] EXC {type(e).__name__}: {e}\n")
    if child is not None: out("\n--- buf ---\n" + (child.before or "")[-2000:] + "\n")
finally:
    try: child.expect(pexpect.EOF, timeout=60)
    except Exception: pass
    try: child.close(force=True)
    except Exception: pass
    os.system("pkill -9 qemu-system-x86 2>/dev/null; pkill -9 swtpm 2>/dev/null")
out("\n====== RESULTS ======\n")
for k, v in results.items(): out(f"  {'PASS' if v else 'FAIL'}  {k}\n")
ap = bool(results) and all(results.values())
out(f"\nOVERALL: {'ALL PASS' if ap else 'FAILURES'}\n"); sys.exit(0 if ap else 1)
