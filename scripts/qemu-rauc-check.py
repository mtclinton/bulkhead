#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Yocto LIVE check for the RAUC A/B atomic update + rollback (ADR-0003 release capability).

The RAUC bundle (verity, efi+rootfs slots) and the A/B wic (root_a=part4 bootname A,
root_b=part5 bootname B, shared /data, grubenv boot-selection) are fully declared, but
nothing exercised an actual slot switch or a failed-update rollback. This is that test —
the headline "atomic A/B update + rollback" reason to ship RAUC at all.

Three boots in ONE qemu process (so the snapshot overlay + shared /data persist across the
in-guest reboots, discarded on exit; the deploy artifacts are never mutated):

  BOOT 1 (slot A): box healthy, booted the A rootfs; `rauc install` the bundle (attached as
                   a raw read-only virtio disk) into the inactive B slot; reboot.
  BOOT 2 (slot B): THE A/B SWITCH — booted the B rootfs (the freshly-installed slot), and it
                   comes up a fully-working enforced bulkhead (collector active). Mark the
                   booted slot bad; reboot.
  BOOT 3 (slot A): THE ROLLBACK — back on the A rootfs, still healthy.

Booted slot = the rootfs partition backing / (from /proc/mounts): part 4 => A, part 5 => B
(robust across sda/vda; findmnt/blockdev are NOT in the minimal image). The bundle disk is
found via /sys/block by size (40-300MB whole disk; the wic is GBs), or by-id if udev made it.
qemu pads a raw drive to a sector boundary, so we copy EXACTLY the bundle bytes (head -c) —
trailing zeros would break rauc's end-of-file signature read. Driven through run-qemu-tpm.sh
(OVMF + swtpm); the bundle disk is attached via BULKHEAD_EXTRA_QEMUPARAMS. Stdlib only.
"""

import os
import re
import select
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNQEMU_TPM = os.path.join(ROOT, "yocto", "scripts", "run-qemu-tpm.sh")
DEPLOY = os.path.join(ROOT, "yocto", "build", "tmp", "deploy", "images", "qemux86-64")
BUNDLE = os.path.join(DEPLOY, "bulkhead-bundle-qemux86-64.raucb")
TIMEOUT = int(os.environ.get("BULKHEAD_RAUC_CHECK_TIMEOUT", "1500"))

# Wait until the box has finished arming before probing (hardened boot: seal -> verify-audit ->
# enforce -> attest gates). Collector active is the readiness signal.
READY = "for i in $(seq 1 90); do systemctl is-active bulkhead-collector >/dev/null 2>&1 && break; sleep 2; done"
# Resolve the device backing / (findmnt is absent; parse /proc/mounts, deref /dev/root if used).
ROOTDEV = [
    'echo "rootdev=$(grep -m1 \' / \' /proc/mounts | cut -d\' \' -f1)"',
    'echo "cmdline=$(cat /proc/cmdline)"',
    # GRUB sets rauc.slot=A|B on the kernel cmdline for the booted slot — the authoritative signal
    # (/ shows as /dev/root, so the device alone is ambiguous).
    "echo \"rauc-slot=$(sed -n 's/.*rauc\\.slot=\\([AB]\\).*/\\1/p' /proc/cmdline)\"",
    'echo "collector-active=$(systemctl is-active bulkhead-collector)"',
]


def boot1_probe(size):
    return [
        READY,
        "echo '<<<BOOT1'",
        *ROOTDEV,
        "rauc status >/tmp/rs1 2>&1",
        "echo \"rauc-compatible=$(grep -c 'bulkhead appliance' /tmp/rs1)\"",
        # find the bundle disk: by-id if udev made it, else the 40-300MB whole disk (wic is GBs).
        "BDEV=/dev/disk/by-id/virtio-raucbundle",
        '[ -b "$BDEV" ] || for d in /sys/block/vd? /sys/block/sd?; do [ -e "$d/size" ] || continue; s=$(cat "$d/size"); [ "$s" -ge 80000 ] && [ "$s" -le 600000 ] && BDEV=/dev/$(basename "$d") && break; done',
        'echo "bundle-dev=$BDEV"',
        'echo "bundle-present=$([ -b "$BDEV" ] && echo yes || echo no)"',
        # copy EXACTLY the bundle bytes (qemu sector-pads the raw drive; trailing zeros break the sig read).
        # busybox is the only toolset (no head -c, no truncate), so: full 512B sectors via dd, then append
        # the sub-sector byte remainder (a tiny bs=1 lseek+read). full=size//512 sectors, rem=size%512 bytes.
        f'dd if="$BDEV" of=/data/bundle.raucb bs=512 count={size // 512} 2>/dev/null',
        f'dd if="$BDEV" bs=1 skip={(size // 512) * 512} count={size % 512} 2>/dev/null >> /data/bundle.raucb',
        'echo "copied-bytes=$(stat -c %s /data/bundle.raucb 2>/dev/null)"',
        "rauc install /data/bundle.raucb >/tmp/ri 2>&1; RC=$?; echo \"install-rc=$RC\"",
        'echo "install-tail=$(tail -n1 /tmp/ri)"',
        '[ "$RC" = 0 ] || sed "s/^/install-log: /" /tmp/ri',  # on FAILURE only, dump the full log
        "rm -f /data/bundle.raucb",
        "echo 'BOOT1END>>>'",
        "systemctl reboot",
    ]


PROBE_BOOT2 = [
    READY,
    "echo '<<<BOOT2'",
    *ROOTDEV,
    'echo "broker-active=$(systemctl is-active bulkhead-broker)"',
    # mark the just-booted (B) slot bad so the next reboot rolls back to A.
    "rauc status mark-bad booted >/tmp/mb 2>&1; echo \"markbad-rc=$?\"",
    'echo "markbad-tail=$(tail -n1 /tmp/mb)"',
    "echo 'BOOT2END>>>'",
    "systemctl reboot",
]

PROBE_BOOT3 = [
    READY,
    "echo '<<<BOOT3'",
    *ROOTDEV,
    "echo 'BOOT3END>>>'",
    "poweroff",
]


def slot_of(dev_or_cmdline):
    # part 4 => slot A, part 5 => slot B (root_a=part4, root_b=part5 in the wks).
    s = dev_or_cmdline or ""
    if re.search(r"(root_b|rootfs\.1)", s) or re.search(r"[a-z]5\b", s):
        return "B"
    if re.search(r"(root_a|rootfs\.0)", s) or re.search(r"[a-z]4\b", s):
        return "A"
    return "?"


def main():
    for p in (RUNQEMU_TPM, BUNDLE):
        if not os.path.exists(p):
            hint = " — run `bitbake bulkhead-image bulkhead-bundle`" if p == BUNDLE else ""
            print(f"missing {p}{hint}", file=sys.stderr)
            return 2
    size = os.path.getsize(os.path.realpath(BUNDLE))

    tpmstate = os.environ.get("BULKHEAD_TPMSTATE") or tempfile.mkdtemp(prefix="bh-rauc-tpm.")
    # if=virtio -> the bundle is the only virtio disk (the wic is virtio-scsi /dev/sda), so the guest
    # sees it as /dev/vda; the probe finds it by size via /sys/block (no `serial=` — raw -drive rejects it).
    extra = f"-drive file={os.path.realpath(BUNDLE)},if=virtio,format=raw,readonly=on,media=disk"
    env = dict(os.environ, BULKHEAD_TPMSTATE=tpmstate, BULKHEAD_EXTRA_QEMUPARAMS=extra)

    proc = subprocess.Popen(
        ["bash", RUNQEMU_TPM, "snapshot"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, bufsize=0, env=env,
    )

    def send(s, chunk=16, delay=0.02):
        data = s.encode()
        try:
            for i in range(0, len(data), chunk):
                proc.stdin.write(data[i:i + chunk])
                proc.stdin.flush()
                time.sleep(delay)
        except (BrokenPipeError, ValueError):
            pass

    def send_probe(lines):
        for ln in lines:
            send(ln + "\n")
            time.sleep(0.5)

    probes = {1: boot1_probe(size), 2: PROBE_BOOT2, 3: PROBE_BOOT3}
    out = []
    boot = 1
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
        full = "".join(out).replace("\r", "")
        tail = full[-400:]
        if not logged_in and re.search(r"login:\s*$", tail):
            send("root\n")
            logged_in = True
            t_login = time.time()
            continue
        if logged_in and tail.endswith("Password: "):
            send("\n")
        if logged_in and not probed and time.time() - t_login > 3:
            send_probe(probes[boot])
            probed = True
            continue
        if boot < 3 and re.search(rf"\n<<<BOOT{boot}\n.*?\nBOOT{boot}END>>>", full, re.S):
            boot += 1
            logged_in = probed = False
            continue
        if re.search(r"\n<<<BOOT3\n.*?\nBOOT3END>>>", full, re.S):
            break

    try:
        proc.wait(timeout=25)
    except subprocess.TimeoutExpired:
        proc.kill()

    text = "".join(out).replace("\r", "")

    def block(n):
        m = re.search(rf"\n<<<BOOT{n}\n(.*?)\nBOOT{n}END>>>", text, re.S)
        return (m.group(1) if m else ""), bool(m)

    def kv(body, key):
        m = re.search(rf"^{re.escape(key)}=(.*)$", body, re.M)
        return m.group(1).strip() if m else None

    b1, ok1 = block(1)
    b2, ok2 = block(2)
    b3, ok3 = block(3)

    def booted_slot(body):
        rs = kv(body, "rauc-slot")
        if rs in ("A", "B"):
            return rs
        return slot_of(kv(body, "cmdline"))

    s1, s2, s3 = booted_slot(b1), booted_slot(b2), booted_slot(b3)

    checks = [
        ("BOOT1 captured", ok1),
        ("boot 1 booted slot A", s1 == "A"),
        ("collector active on A", kv(b1, "collector-active") == "active"),
        ("rauc sees the bulkhead-appliance system", kv(b1, "rauc-compatible") == "1"),
        ("bundle disk attached + readable", kv(b1, "bundle-present") == "yes"),
        ("exact bundle bytes copied to /data", kv(b1, "copied-bytes") == str(size)),
        ("rauc install into the inactive slot succeeded", kv(b1, "install-rc") == "0"),
        ("BOOT2 captured (reboot after install)", ok2),
        ("A/B SWITCH: boot 2 booted slot B", s2 == "B"),
        ("the freshly-installed B slot is a working enforced bulkhead (collector active)", kv(b2, "collector-active") == "active"),
        ("broker active on B", kv(b2, "broker-active") == "active"),
        ("rauc mark-bad (booted B) succeeded", kv(b2, "markbad-rc") == "0"),
        ("BOOT3 captured (reboot after mark-bad)", ok3),
        ("ROLLBACK: boot 3 fell back to slot A", s3 == "A"),
        ("collector active on A after rollback", kv(b3, "collector-active") == "active"),
    ]

    print("\n\n=== bulkhead RAUC A/B update + rollback verification ===")
    print(f"INFO: booted slots — b1={s1} b2={s2} b3={s3} "
          f"(rootdev b1={kv(b1, 'rootdev')} b2={kv(b2, 'rootdev')} b3={kv(b3, 'rootdev')})")
    print(f"INFO: install-tail={kv(b1, 'install-tail')!r}  markbad-tail={kv(b2, 'markbad-tail')!r}")
    ok = True
    for name, cond in checks:
        print(("PASS" if cond else "FAIL") + ": " + name)
        ok = ok and cond
    print("RAUC A/B UPDATE+ROLLBACK OK" if ok else "RAUC A/B UPDATE+ROLLBACK INCOMPLETE")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
