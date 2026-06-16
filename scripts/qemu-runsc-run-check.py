#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# ADR-0031 substrate integration, slice 5: the PRODUCTION runtime form. `runsc do` is "testing only";
# the deployable runtime is `runsc run` over an OCI bundle. And a real jail needs a MINIMAL rootfs —
# root=/ would expose the whole host fs to the agent (a regression vs the systemd jail's
# ProtectSystem=strict). So this builds a minimal rootfs (only the agent binary + the two UDS legs
# bind-mounted in) and runs the real agent loop under `runsc run`, with both mediated channels intact.
# Proves the secure production form works before it is packaged into a recipe/wrapper/systemd unit.
#
# security-review R3: the two UDS legs are bind-mounted READ-ONLY (matching the launcher). The agent
# loop reaching HTTP 200 proves connect() still works through a ro-mounted socket under gVisor (a
# socket inode is exempt from the RO-mount write check); a follow-up `probe-romount` run then proves
# unlink/create of the shared egress.sock is refused EROFS — closing a cross-tier socket-unlink DoS.
# Boots the wic (slirp); stdlib + pexpect.
import pexpect, sys, os, re
BUILD = "/home/work/ideas/bulkhead/yocto/build"
def out(s): sys.stdout.write(s); sys.stdout.flush()
inner = (f"cd {BUILD} && source ../poky/oe-init-build-env . >/dev/null 2>&1 && "
         f"exec runqemu qemux86-64 wic ovmf nographic kvm slirp")
PS = "BHX_PROMPT> "; results = {}; child = None
def check(c, l): results[l] = bool(c); out(f"\n[CHECK] {'PASS' if c else 'FAIL'}: {l}\n")
def login(c):
    c.expect("login:", timeout=300); c.sendline("root")
    i = c.expect(["Password:", r"@qemux86-64:~#"], timeout=60)
    if i == 0: c.sendline(""); c.expect(r"@qemux86-64:~#", timeout=30)
    c.sendline(f"export PS1='{PS}'"); c.expect(PS, timeout=30); c.expect(PS, timeout=30)
# The secure minimal-rootfs OCI config (one line; only the agent + UDS legs are bind-mounted in).
CONFIG = ('{"ociVersion":"1.0.0","process":{"user":{"uid":0,"gid":0},'
    '"args":["/usr/bin/bulkhead-agent","runscjob"],'
    '"env":["PATH=/usr/bin:/bin","BULKHEAD_ROUTER_UDS=/run/bulkhead-router/router.sock",'
    '"BULKHEAD_EGRESS_SOCK=/run/bulkhead-egress/egress.sock","BULKHEAD_AGENT_TASK=FETCH-ONLY run",'
    '"BULKHEAD_AGENT_DEADLINE=60"],"cwd":"/","capabilities":{"bounding":[],"effective":[],'
    '"inheritable":[],"permitted":[]},"rlimits":[{"type":"RLIMIT_NOFILE","hard":1024,"soft":1024}]},'
    '"root":{"path":"rootfs","readonly":true},"hostname":"runsc","mounts":['
    '{"destination":"/proc","type":"proc","source":"proc"},'
    '{"destination":"/dev","type":"tmpfs","source":"tmpfs"},'
    '{"destination":"/sys","type":"sysfs","source":"sysfs","options":["nosuid","noexec","nodev","ro"]},'
    '{"destination":"/usr/bin/bulkhead-agent","type":"bind","source":"/usr/bin/bulkhead-agent","options":["bind","ro"]},'
    '{"destination":"/run/bulkhead-egress","type":"bind","source":"/run/bulkhead-egress","options":["bind","ro"]},'
    '{"destination":"/run/bulkhead-router","type":"bind","source":"/run/bulkhead-router","options":["bind","ro"]}],'
    '"linux":{"namespaces":[{"type":"pid"},{"type":"network"},{"type":"ipc"},{"type":"uts"},{"type":"mount"}]}}')
# security-review R3: the SAME bundle, but the agent runs `probe-romount` — from inside the ro-leg
# sandbox it confirms connect() still works yet unlink/create of the shared egress.sock is REFUSED
# (gVisor surfaces a ro-mount write as EACCES/EPERM, not EROFS — either is a refusal).
CONFIG_ROM = (CONFIG
    .replace('"args":["/usr/bin/bulkhead-agent","runscjob"]', '"args":["/usr/bin/bulkhead-agent","probe-romount"]')
    .replace('"BULKHEAD_AGENT_TASK=FETCH-ONLY run"', '"BULKHEAD_PROBE_TARGET=127.0.0.1:8088"'))
# COUNTERFACTUAL: the SAME leg dir bind-mounted READ-WRITE (the pre-fix config), sock unset so the
# probe only does the non-destructive CREATE in /run/bulkhead-egress. A write that the ro mount
# REFUSES is ALLOWED here — proving the ro mount is causally what closes the DoS (the finding was real,
# not already-safe), and that gVisor's refusal above is the mount, not some blanket host-DAC denial.
CONFIG_RW = (CONFIG_ROM
    .replace('"source":"/run/bulkhead-egress","options":["bind","ro"]', '"source":"/run/bulkhead-egress","options":["bind","rw"]')
    .replace('"BULKHEAD_EGRESS_SOCK=/run/bulkhead-egress/egress.sock"', '"BULKHEAD_ROMOUNT_DIR=/run/bulkhead-egress"'))
try:
    child = pexpect.spawn("/bin/bash", ["-c", inner], timeout=300, encoding="utf-8", codec_errors="replace")
    child.logfile_read = sys.stdout
    login(child)
    def run(c, t=90): child.sendline(c); child.expect(PS, timeout=t); return child.before

    check("runsc version" in run("runsc --version 2>&1"), "runsc present")
    # Model + web backends (mockchat is both the canned upstream and the loopback fetch target).
    run("mkdir -p /run/systemd/system/bulkhead-mockchat.service.d")
    run("printf '[Service]\\nEnvironment=BULKHEAD_MOCKCHAT_TARGET=http://127.0.0.1:8088/v1/chat/completions\\n'"
        " > /run/systemd/system/bulkhead-mockchat.service.d/10-target.conf")
    run("systemctl daemon-reload 2>&1"); run("systemctl restart bulkhead-mockchat.service 2>&1"); run("sleep 1 2>/dev/null; true")
    check("active" in run("systemctl is-active bulkhead-mockchat.service 2>&1"), "mockchat upstream active")
    run("mkdir -p /run/systemd/system/bulkhead-router.service.d")
    run("printf '[Service]\\nEnvironment=BULKHEAD_LLAMA_URL=http://127.0.0.1:8088\\n'"
        " > /run/systemd/system/bulkhead-router.service.d/90-test-local.conf")
    run("systemctl daemon-reload 2>&1"); run("systemctl restart bulkhead-router.service 2>&1"); run("sleep 2 2>/dev/null; true")
    check("RUDS=yes" in run("echo RUDS=$([ -S /run/bulkhead-router/router.sock ] && echo yes || echo no)"), "router UDS exists")
    run("printf '127.0.0.1\\n' > /run/egress-allow-test.conf")
    run("mkdir -p /run/systemd/system/bulkhead-egress-proxy.service.d")
    run("printf '[Service]\\nEnvironment=BULKHEAD_EGRESS_ALLOWLIST=/run/egress-allow-test.conf\\n"
        "Environment=BULKHEAD_EGRESS_ALLOW_INTERNAL_CIDRS=127.0.0.0/8\\n'"
        " > /run/systemd/system/bulkhead-egress-proxy.service.d/10-test.conf")
    run("systemctl daemon-reload 2>&1"); run("systemctl restart bulkhead-egress-proxy.service 2>&1"); run("sleep 1 2>/dev/null; true")
    check("active" in run("systemctl is-active bulkhead-egress-proxy.service 2>&1"), "egress proxy active with test allowlist")

    # Build the OCI bundle: a MINIMAL rootfs (just the bind-mount points) + the secure config.
    run("rm -rf /run/oci && mkdir -p /run/oci/rootfs/usr/bin /run/oci/rootfs/run/bulkhead-egress /run/oci/rootfs/run/bulkhead-router /run/oci/rootfs/proc /run/oci/rootfs/dev /run/oci/rootfs/sys")
    run("touch /run/oci/rootfs/usr/bin/bulkhead-agent")  # bind-mount point for the agent binary
    # Write config.json in CHUNKS: a single ~1.4 KB console line exceeds the pty canonical input
    # limit, gets truncated mid-string, and leaves an unclosed quote (bash -> "> " continuation).
    run("rm -f /run/oci/config.json")
    for i in range(0, len(CONFIG), 480):
        run(f"printf '%s' '{CONFIG[i:i+480]}' >> /run/oci/config.json")
    check("CFGOK=yes" in run("echo CFGOK=$(grep -q ociVersion /run/oci/config.json && echo yes || echo no)"),
          "OCI bundle config.json staged")
    check("NOHOSTFS=yes" in run("echo NOHOSTFS=$([ ! -e /run/oci/rootfs/etc ] && echo yes || echo no)"),
          "minimal rootfs — the host fs is NOT exposed (no /etc etc.), only the agent + UDS legs are bind-mounted")

    chain = "/data/bulkhead/audit-egress/provenance.jsonl"
    nb = re.search(r"NB=(\d+)", run(f"echo NB=$(grep -c '\"hook\":\"connect\"' {chain} 2>/dev/null || echo 0)"))
    nbefore = int(nb.group(1)) if nb else -1

    # PRODUCTION FORM: runsc run over the OCI bundle. network=none; host-uds=open for the mediated legs.
    ro = run("runsc --host-uds=open --rootless --ignore-cgroups --platform=systrap --network=none "
             "run -bundle /run/oci runscjob 2>&1; echo RUN_RC=$?", t=180)
    out(f"\n[runsc run — agent loop in a minimal-rootfs sandbox]\n{ro}\n")

    check(bool(re.search(r"agent\[runscjob\]: DONE", ro)),
          "the agent loop ran under `runsc run` (minimal rootfs) and reached DONE — model leg over the router UDS worked")
    check("OK: fetch 127.0.0.1:8088 -> HTTP 200" in ro,
          "R3: the web leg worked THROUGH the READ-ONLY egress UDS mount (HTTP 200) — connect() on a ro socket mount under gVisor is unaffected")
    na = re.search(r"NA=(\d+)", run(f"echo NA=$(grep -c '\"hook\":\"connect\"' {chain} 2>/dev/null || echo 0)"))
    nafter = int(na.group(1)) if na else -1
    va = run(f"bulkhead-collector verify-audit {chain} 2>&1; echo VA_RC=$?", t=30)
    check(nbefore >= 0 and nafter > nbefore, f"the runsc-run agent's egress was SIGNED into the chain ({nbefore} -> {nafter})")
    check("VA_RC=0" in va and "domain: egress-proxy" in va, "the egress chain still verifies signed")
    run("runsc --rootless --ignore-cgroups delete -force runscjob 2>/dev/null; true")

    # ===== security-review R3: re-run the SAME ro-leg bundle as `probe-romount`. The legs are mounted
    #       read-only, so from inside the sandbox a connect() still works but unlink/create of the
    #       shared egress.sock must EROFS — a sandboxed agent cannot DoS the other tiers by removing
    #       the one socket they all egress through. (The agent loop above already proved egress works
    #       on the ro mount; this proves the write surface is genuinely closed under gVisor.) =====
    run("rm -f /run/oci/config.json")
    for i in range(0, len(CONFIG_ROM), 480):
        run(f"printf '%s' '{CONFIG_ROM[i:i+480]}' >> /run/oci/config.json")
    rom = run("runsc --host-uds=open --rootless --ignore-cgroups --platform=systrap --network=none "
              "run -bundle /run/oci runscrom 2>&1; echo ROM_RC=$?", t=120)
    out(f"\n[runsc run — probe-romount in the ro-leg sandbox]\n{rom}\n")
    check("PROBE ROMOUNT-CONNECT: OK" in rom,
          "R3: connect() to the egress proxy STILL works through the ro-mounted UDS (mediated egress unaffected)")
    # gVisor surfaces a read-only-mount write as EACCES/EPERM (not Linux's EROFS) — accept any REFUSED-*.
    check("PROBE ROMOUNT-UNLINK: REFUSED" in rom,
          "R3: unlink(egress.sock) is REFUSED — a sandboxed agent cannot remove the shared socket (cross-tier DoS closed)")
    check("PROBE ROMOUNT-CREATE: REFUSED" in rom,
          "R3: creating an entry in the egress leg dir is REFUSED — no rogue replacement socket can be planted")
    run("runsc --rootless --ignore-cgroups delete -force runscrom 2>/dev/null; true")

    # COUNTERFACTUAL: re-run the SAME leg dir mounted READ-WRITE (sock unset -> CREATE-only, never
    # touches the real socket). The write the ro mount just refused is ALLOWED here, proving the ro
    # mount is what closes the DoS — not a host-DAC accident that would have blocked rw too.
    run("rm -f /run/oci/config.json")
    for i in range(0, len(CONFIG_RW), 480):
        run(f"printf '%s' '{CONFIG_RW[i:i+480]}' >> /run/oci/config.json")
    rw = run("runsc --host-uds=open --rootless --ignore-cgroups --platform=systrap --network=none "
             "run -bundle /run/oci runscrw 2>&1; echo RW_RC=$?", t=120)
    out(f"\n[runsc run — probe-romount counterfactual, leg dir mounted RW]\n{rw}\n")
    check("PROBE ROMOUNT-CREATE: ALLOWED" in rw,
          "R3 counterfactual: with the leg dir mounted RW the same CREATE SUCCEEDS — the ro mount is causally what refuses it (the finding was real)")
    run("runsc --rootless --ignore-cgroups delete -force runscrw 2>/dev/null; true")
    # the counterfactual must NOT have left its probe file behind in the real leg dir.
    check("LEFT=no" in run("echo LEFT=$([ -e /run/bulkhead-egress/romount-probe ] && echo yes || echo no)"),
          "R3 counterfactual cleaned up — no stray file left in the live egress leg dir")
    run("systemctl stop bulkhead-mockchat.service 2>&1")
    run("poweroff", t=20)
except Exception as e:
    out(f"\n[harness] EXC {type(e).__name__}: {e}\n")
    if child is not None: out("\n--- buf ---\n" + (child.before or "")[-2000:] + "\n")
finally:
    try: child.expect(pexpect.EOF, timeout=60)
    except Exception: pass
    try: child.close(force=True)
    except Exception: pass
    os.system("pkill -9 qemu-system-x86 2>/dev/null")
out("\n====== RESULTS ======\n")
for k, v in results.items(): out(f"  {'PASS' if v else 'FAIL'}  {k}\n")
ap = bool(results) and all(results.values())
out(f"\nOVERALL: {'ALL PASS' if ap else 'FAILURES'}\n"); sys.exit(0 if ap else 1)
