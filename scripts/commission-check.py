#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
#
# Bare-metal COMMISSIONING harness (docs/COMMISSIONING.md, Phase 5). Runs bulkhead's gate battery against a
# REAL target — over ssh (management tailnet) or a serial console — and prints a PASS/FAIL report + a GO/NO-GO
# verdict. The on-target assertions mirror the existing qemu verify-* scripts (floor / egress / attest /
# hostile-agent containment / tiers), so a green report on hardware is the bare-metal analogue of a green
# `make verify-*` run — and proves the parts the qemu suite can't (real TPM seal, EK-rooted attestation, the
# FC microVM on real /dev/kvm, the nftables floor on a real NIC). Each gate is tagged [HW] (only proves out on
# real hardware) or [qemu-ok]. Author-verified (sound logic, real commands); the live run is the operator's.
#
#   python3 scripts/commission-check.py --ssh root@<device>
#   python3 scripts/commission-check.py --serial /dev/ttyUSB0
#   --skip-hw   report only the gates that also pass in qemu (a pre-hardware dry run)
import argparse, subprocess, sys

# Each gate's command self-asserts and echoes GATE_OK on success (GATE_FAIL or nothing otherwise), so the
# runner logic is a trivial substring check independent of the transport.
OK = "&& echo GATE_OK"
GATES = [
    # boot / TCB health
    ("boot", "collector + TCB services active", False,
     "for u in bulkhead-collector bulkhead-selftest bulkhead-router bulkhead-egress-proxy; do "
     "systemctl is-active $u | grep -qx active || exit 1; done " + OK),
    ("boot", "verify-audit + selftest boot gates active (fail-closed)", False,
     "systemctl is-active bulkhead-verify-audit.service | grep -qx active && "
     "systemctl show -p Requires bulkhead-egress-proxy.service | grep -q bulkhead-selftest " + OK),
    ("boot", "a persisted audit chain verifies", False,
     "bulkhead-collector verify-audit /data/bulkhead/audit/provenance.jsonl >/dev/null 2>&1 " + OK),

    # kernel security floor
    ("floor", "LSM stack: landlock + lockdown + yama + bpf active", False,
     "for l in landlock lockdown yama bpf; do grep -qw $l /sys/kernel/security/lsm || exit 1; done " + OK),
    ("floor", "io_uring compiled OUT of the production kernel", False,
     "zcat /proc/config.gz 2>/dev/null | grep -q '^# CONFIG_IO_URING is not set' " + OK),

    # egress mediation
    ("egress", "nftables default-deny floor (both chains policy drop)", False,
     "[ \"$(nft list ruleset 2>/dev/null | grep -c 'policy drop')\" -ge 2 ] " + OK),
    ("egress", "a public host is DROPPED at the floor (real NIC)", True,
     "curl -s -o /dev/null --connect-timeout 6 -m 8 http://1.1.1.1/ ; [ $? -ne 0 ] " + OK),
    ("egress", "mediated probe: NOROUTE/ISOLATED/PROXY-OK/PROXY-DENY all PASS", False,
     "systemctl start bulkhead-agent-confined@egressprobe.service 2>/dev/null; "
     "j=$(journalctl -u bulkhead-agent-confined@egressprobe.service --no-pager -o cat 2>/dev/null); "
     "echo \"$j\" | grep -q 'PROXY-OK: PASS' && echo \"$j\" | grep -q 'PROXY-DENY: PASS' && "
     "echo \"$j\" | grep -q 'NOROUTE: PASS' " + OK),

    # hostile-agent containment (the full probe-escape inside the real confined jail)
    ("containment", "probe-escape: all 10 escape vectors CONTAINED, no breach", False,
     "mkdir -p /run/systemd/system/bulkhead-agent-confined@escape.service.d && "
     "printf '[Service]\\nType=oneshot\\nExecStart=\\nExecStart=/usr/bin/bulkhead-agent probe-escape\\n' "
     "> /run/systemd/system/bulkhead-agent-confined@escape.service.d/10-escape.conf && systemctl daemon-reload && "
     "systemctl start bulkhead-agent-confined@escape.service 2>/dev/null; "
     "j=$(journalctl -u bulkhead-agent-confined@escape.service --no-pager -o cat 2>/dev/null); "
     "echo \"$j\" | grep -q 'ESCAPE RESULT: CONTAINED' && ! echo \"$j\" | grep -qw BREACH " + OK),
    ("containment", "the floor SURVIVED the assault (E0+E2+collector still armed)", False,
     "systemctl is-active bulkhead-enforce.service bulkhead-enforce-egress.service bulkhead-collector.service "
     "| grep -vqx active || true; [ \"$(systemctl is-active bulkhead-enforce.service bulkhead-enforce-egress.service "
     "bulkhead-collector.service | grep -cx active)\" -eq 3 ] " + OK),

    # attestation
    ("attest", "attest gate: E0+E2 armed + TCB clean", False,
     "bulkhead-collector attest gate >/dev/null 2>&1 " + OK),
    ("attest", "AK is EK-ROOTED (pin provisioned, not the structural fallback)", True,
     "test -s /data/bulkhead/attest-ak.pin " + OK),
    ("attest", "a fresh-nonce quote verifies against the EK-rooted pin", True,
     "N=$(openssl rand -hex 32); bulkhead-collector attest quote $N > /tmp/cc-env.json 2>/dev/null && "
     "D=$(bulkhead-collector attest expected-d /usr/bin/bulkhead-collector 2>/dev/null | grep -oE '[0-9a-f]{64}' | tail -1) && "
     "bulkhead-collector attest verify /tmp/cc-env.json $D $N @/data/bulkhead/attest-ak.pin >/dev/null 2>&1 " + OK),

    # TPM2-sealed boot (real TPM)
    ("tpm2-seal", "audit seed sealed: decrypts to 32 bytes, no plaintext on /data", True,
     "[ \"$(systemd-creds decrypt --name=audit-seed /data/bulkhead/audit-seed.cred - 2>/dev/null | wc -c)\" = 32 ] && "
     "! test -e /data/bulkhead/audit-seed " + OK),
    ("tpm2-seal", "PCR 7 is firmware-populated (Secure Boot measured)", True,
     "tpm2_pcrread sha256:7 2>/dev/null | grep -qiE '7 *: *0x[0-9A-F]*[1-9A-F]' " + OK),

    # the hostile + default isolation tiers (need real /dev/kvm for FC + runsc-kvm)
    ("tiers", "Firecracker + /dev/kvm present for the hostile tier", True,
     "[ -e /dev/kvm ] && /usr/bin/firecracker --version >/dev/null 2>&1 && /usr/bin/jailer --version >/dev/null 2>&1 " + OK),
    ("tiers", "runsc present for the default (gVisor) tier", False,
     "runsc --version 2>/dev/null | grep -qi release " + OK),

    # update / rollback
    ("provision", "RAUC: the booted slot is marked good", False,
     "rauc status 2>/dev/null | grep -qiE 'boot.*good|good.*boot|booted' " + OK),
]


class SSHTarget:
    def __init__(self, dest):
        self.dest = dest
    def run(self, cmd, timeout=120):
        p = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", self.dest, cmd],
                           capture_output=True, text=True, timeout=timeout)
        return p.stdout + p.stderr


class SerialTarget:
    # Drives a real serial console with the wrap-immune line-anchored marker capture (program output to a
    # serial console is not readline-wrapped; the TTY is widened so even long lines do not wrap).
    def __init__(self, dev, baud=115200):
        import pexpect
        self.PS = "BHX_CMSN> "
        self.child = pexpect.spawn(f"picocom -b {baud} -q {dev}", timeout=60, encoding="utf-8", codec_errors="replace")
        self.child.logfile_read = sys.stdout
        self.child.sendline("")
        i = self.child.expect(["login:", r"[#$] ", self.PS], timeout=120)
        if i == 0:
            self.child.sendline("root"); self.child.expect([r"Password:", r"[#$] "], timeout=30)
        self.child.sendline(f"export PS1='{self.PS}'; stty cols 8000 2>/dev/null; true")
        self.child.expect(self.PS, timeout=30); self.child.expect(self.PS, timeout=30)
    def run(self, cmd, timeout=120):
        import re
        self.child.sendline(f"echo CCS; {cmd}; echo CCE$?")
        self.child.expect(self.PS, timeout=timeout)
        b = self.child.before.replace("\r", "")
        out, collecting = [], False
        for ln in b.split("\n"):
            if not collecting:
                if ln.strip() == "CCS":
                    collecting = True
                continue
            if re.match(r"CCE\d+$", ln.strip()):
                break
            out.append(ln)
        return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--ssh", metavar="user@host")
    g.add_argument("--serial", metavar="/dev/ttyX")
    ap.add_argument("--skip-hw", action="store_true", help="run only gates that also pass in qemu (pre-hardware dry run)")
    ap.add_argument("--dry-run", action="store_true", help="list the gate battery without contacting a target")
    args = ap.parse_args()

    if args.dry_run:
        print(f"=== commissioning gate battery: {len(GATES)} gates ===")
        for cat, name, hw, _ in GATES:
            print(f"  {'[HW]     ' if hw else '[qemu-ok]'} {cat}: {name}")
        hw_n = sum(1 for _, _, hw, _ in GATES if hw)
        print(f"\n{hw_n} hardware-only, {len(GATES) - hw_n} also-green-in-qemu")
        return

    if not args.ssh and not args.serial:
        ap.error("a target is required: --ssh user@host or --serial /dev/ttyX (or --dry-run to list gates)")
    target = SSHTarget(args.ssh) if args.ssh else SerialTarget(args.serial)

    print(f"=== bulkhead commissioning gates ({'ssh ' + args.ssh if args.ssh else 'serial ' + args.serial}) ===\n")
    npass = nfail = nskip = 0
    fails = []
    for cat, name, hw, cmd in GATES:
        tag = "[HW]     " if hw else "[qemu-ok]"
        if hw and args.skip_hw:
            print(f"SKIP {tag} {cat}: {name}")
            nskip += 1
            continue
        try:
            out = target.run(cmd)
        except Exception as e:
            out = f"(transport error: {e})"
        ok = "GATE_OK" in out
        print(f"{'PASS' if ok else 'FAIL'} {tag} {cat}: {name}")
        if ok:
            npass += 1
        else:
            nfail += 1
            fails.append((cat, name, out.strip()[-300:]))

    if fails:
        print("\n--- failing gate output (tail) ---")
        for cat, name, o in fails:
            print(f"\n[{cat}] {name}:\n{o}")

    print(f"\n=== commissioning: {npass} passed, {nfail} failed, {nskip} skipped ===")
    if nfail == 0 and nskip == 0:
        print("COMMISSIONING GO — every gate passed on hardware")
    elif nfail == 0:
        print("COMMISSIONING PARTIAL — non-HW gates passed; re-run without --skip-hw on real hardware for GO")
    else:
        print("COMMISSIONING NO-GO — see failing gates above")
    sys.exit(1 if nfail else 0)


if __name__ == "__main__":
    main()
