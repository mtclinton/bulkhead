#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Verify ADR-0034 increment 2 (TLS-termination + content inspection) live, in the confined jail.
# inc1 proves PLACEMENT (the agent can only reach the net via the proxy); this proves the proxy can
# now SEE and rule on the content of an allowed TLS flow. Boots the wic and asserts:
#
#   provision: bulkhead-provision-mitm-ca.service made /data/bulkhead/mitm-ca/{ca.key(0600),ca.crt,
#              agent-trust.crt}; SSL_CERT_FILE is set in the confined jail and the proxy CA is in the
#              agent-trust bundle.
#   ARM 1 (inspect): a real confined agent fetches https://127.0.0.1:8443 (marked `inspect`) THROUGH
#              the TERMINATING proxy and gets HTTP 200 — proving it trusted the proxy's minted leaf
#              AND the proxy verified the real upstream cert. The egress chain gains a Hook=connect
#              ALLOW and a Hook=inspect record (Mode showing method=GET); verify-audit stays OK.
#   ARM 2 (passthrough): the SAME host re-marked `passthrough` is spliced OPAQUE — the agent still
#              gets 200 (end-to-end TLS to the upstream it now trusts), and the proxy records an
#              explicit Hook=passthrough (reason=default), not an inspect. The coverage ledger is honest.
#
# No internet, no LLM, no real CA: the model leg is the plain mockchat the router already uses; the
# fetch upstream is a second self-signed TLS mockchat; the proxy validates it via an injected upstream
# root. Boots the wic (slirp); stdlib + pexpect. First live exercise of the agent's TLS fetch path.
import pexpect, sys, os, re
BUILD = "/home/work/ideas/bulkhead/yocto/build"
def out(s): sys.stdout.write(s); sys.stdout.flush()
inner = (f"cd {BUILD} && source ../poky/oe-init-build-env . >/dev/null 2>&1 && "
         f"exec runqemu qemux86-64 wic ovmf nographic kvm slirp")
PS = "BHX_PROMPT> "; results = {}; child = None
CHAIN = "/data/bulkhead/audit-egress/provenance.jsonl"
def check(c, l): results[l] = bool(c); out(f"\n[CHECK] {'PASS' if c else 'FAIL'}: {l}\n")
def login(c):
    c.expect("login:", timeout=300); c.sendline("root")
    i = c.expect(["Password:", r"@qemux86-64:~#"], timeout=60)
    if i == 0: c.sendline(""); c.expect(r"@qemux86-64:~#", timeout=30)
    c.sendline(f"export PS1='{PS}'"); c.expect(PS, timeout=30); c.expect(PS, timeout=30)
try:
    child = pexpect.spawn("/bin/bash", ["-c", inner], timeout=300, encoding="utf-8", codec_errors="replace")
    child.logfile_read = sys.stdout
    login(child)
    def run(c, t=90): child.sendline(c); child.expect(PS, timeout=t); return child.before
    def count(hook): return run(f"echo CNT=$(grep -c '\"hook\":\"{hook}\"' {CHAIN} 2>/dev/null || echo 0)")
    def n(s, key): m = re.search(rf"{key}=(\d+)", s); return int(m.group(1)) if m else -1

    check("active" in run("systemctl is-active bulkhead-egress-proxy.service 2>&1"), "egress proxy active at boot")
    check("active" in run("systemctl is-active bulkhead-router.service 2>&1"), "router active at boot")

    # --- provision assertions: the on-device re-signing CA exists, fail-closed, and the agent trusts it ---
    check("active" in run("systemctl is-active bulkhead-provision-mitm-ca.service 2>&1"), "provision-mitm-ca active (CA minted)")
    files = run("echo CA=$([ -f /data/bulkhead/mitm-ca/ca.key ] && [ -f /data/bulkhead/mitm-ca/ca.crt ] && [ -f /data/bulkhead/mitm-ca/agent-trust.crt ] && echo yes || echo no)")
    check("CA=yes" in files, "CA key+cert+agent-trust present on /data")
    check("600" in run("echo KM=$(stat -c '%a' /data/bulkhead/mitm-ca/ca.key 2>/dev/null)"), "ca.key is 0600")
    # the agent-trust bundle is non-empty (proxy CA ++ Web-PKI roots); ARM 1 succeeding then proves
    # the proxy CA specifically is trusted (the agent validates the proxy's minted leaf against it).
    check(n(run("echo TRUST=$(grep -c 'BEGIN CERTIFICATE' /data/bulkhead/mitm-ca/agent-trust.crt 2>/dev/null || echo 0)"), "TRUST") >= 1,
          "agent-trust.crt carries certificate(s) (proxy CA ++ roots)")
    check("agent-trust.crt" in run("systemctl cat bulkhead-agent-confined@.service 2>&1 | grep SSL_CERT_FILE; true"),
          "confined jail sets SSL_CERT_FILE -> agent-trust bundle")
    # the trust file must be reachable by the agent's non-root DynamicUser (dir chain o+x, file o+r) —
    # a regression guard for the CA-dir-perms bug. Parse the modes (runuser isn't on the image).
    diag = run("stat -c 'MODE %n %a' /data/bulkhead/mitm-ca /data/bulkhead/mitm-ca/agent-trust.crt 2>&1")
    out("\n[DIAG trust modes]\n" + diag)
    dm = re.search(r"MODE /data/bulkhead/mitm-ca (\d+)", diag)
    fm = re.search(r"agent-trust\.crt (\d+)", diag)
    readable = bool(dm) and bool(fm) and (int(dm.group(1), 8) & 0o001) and (int(fm.group(1), 8) & 0o004)
    check(readable, "CA dir is o+x and agent-trust.crt is o+r (the non-root agent can load it)")

    # --- bring up the two mockchats: #1 plain (the router's model backend), #2 TLS (the fetch upstream) ---
    run("mkdir -p /run/systemd/system/bulkhead-mockchat.service.d")
    run("printf '[Service]\\nEnvironment=BULKHEAD_MOCKCHAT_TARGET=https://127.0.0.1:8443/v1/chat/completions\\n'"
        " > /run/systemd/system/bulkhead-mockchat.service.d/10-target.conf")
    run("systemctl daemon-reload 2>&1"); run("systemctl restart bulkhead-mockchat.service 2>&1"); run("sleep 1; true")
    check("active" in run("systemctl is-active bulkhead-mockchat.service 2>&1"), "mockchat #1 (plain 8088) model backend active")
    # mockchat #2: a TLS upstream on 8443, writing its self-signed cert for the proxy + agent to trust.
    run("systemd-run --unit=mockchat-tls --collect -p Type=exec "
        "-E BULKHEAD_MOCKCHAT_TLS=1 -E BULKHEAD_MOCKCHAT_ADDR=127.0.0.1:8443 -E BULKHEAD_MOCKCHAT_CERT_OUT=/run/mockchat-cert.pem "
        "/usr/bin/bulkhead-agent mockchat 2>&1")
    run("sleep 1; true")
    check("yes" in run("echo C=$([ -s /run/mockchat-cert.pem ] && echo yes || echo no)"), "mockchat #2 (TLS 8443) up, cert published")
    # the agent must also trust mockchat #2's real cert for the passthrough arm's end-to-end TLS.
    run("cat /run/mockchat-cert.pem >> /data/bulkhead/mitm-ca/agent-trust.crt 2>&1")

    # router local backend -> plain mockchat #1.
    run("mkdir -p /run/systemd/system/bulkhead-router.service.d")
    run("printf '[Service]\\nEnvironment=BULKHEAD_LLAMA_URL=http://127.0.0.1:8088\\n'"
        " > /run/systemd/system/bulkhead-router.service.d/90-test-local.conf")
    run("systemctl daemon-reload 2>&1"); run("systemctl restart bulkhead-router.service 2>&1"); run("sleep 2; true")
    check("RSTATE=active" in run("echo RSTATE=$(systemctl is-active bulkhead-router.service)"), "router restarted (mockchat backend), stable")

    def set_proxy(mode, tls_ports="8443", default_mode=""):
        # allowlist 127.0.0.1 with <mode> (empty = UNMARKED), opt 127/8 past the internal-IP deny, mark
        # <tls_ports> the TLS port set, optionally set the default-mode knob, and trust mockchat #2's
        # cert as an upstream root. tls_ports defaults to 8443 (the fetch port); ARM 3 passes a port that
        # EXCLUDES 8443 so an inspect host is non-terminable; ARM 4 leaves the entry UNMARKED + knob=inspect.
        run(f"printf '127.0.0.1 {mode}\\n' > /run/egress-allow-test.conf")
        run("mkdir -p /run/systemd/system/bulkhead-egress-proxy.service.d")
        run("printf '[Service]\\n"
            "Environment=BULKHEAD_EGRESS_ALLOWLIST=/run/egress-allow-test.conf\\n"
            "Environment=BULKHEAD_EGRESS_ALLOW_INTERNAL_CIDRS=127.0.0.0/8\\n"
            f"Environment=BULKHEAD_EGRESS_TLS_PORTS={tls_ports}\\n"
            f"Environment=BULKHEAD_EGRESS_DEFAULT_MODE={default_mode}\\n"
            "Environment=BULKHEAD_EGRESS_UPSTREAM_ROOTS=/run/mockchat-cert.pem\\n'"
            " > /run/systemd/system/bulkhead-egress-proxy.service.d/50-test.conf")
        run("systemctl daemon-reload 2>&1"); run("systemctl restart bulkhead-egress-proxy.service 2>&1"); run("sleep 1; true")

    def run_agent(inst):
        run(f"mkdir -p /run/systemd/system/bulkhead-agent-confined@{inst}.service.d")
        run("printf '[Service]\\nType=oneshot\\nExecStart=\\n"
            f"ExecStart=/usr/bin/bulkhead-agent {inst}\\n"
            "Environment=\"BULKHEAD_AGENT_TASK=FETCH-ONLY run\"\\n'"
            f" > /run/systemd/system/bulkhead-agent-confined@{inst}.service.d/10-real.conf")
        run("systemctl daemon-reload 2>&1")
        sout = run(f"systemctl start bulkhead-agent-confined@{inst}.service 2>&1; echo SRC=$?", t=150)
        jr = run(f"journalctl -u bulkhead-agent-confined@{inst}.service --no-pager 2>&1 | tail -25")
        return sout, jr

    # ===== ARM 1: inspect — the proxy TERMINATES and inspects =====
    insp_before = n(count("inspect"), "CNT")
    set_proxy("inspect")
    check("active" in run("systemctl is-active bulkhead-egress-proxy.service 2>&1"), "[inspect] proxy restarted with inspect allowlist")
    sout, jr = run_agent("mitminspect")
    out("\n[inspect agent journal]\n" + jr)
    check("SRC=0" in sout, "[inspect] confined agent reached FINAL (exit 0)")
    check(bool(re.search(r"OK: fetch 127\.0\.0\.1:8443 -> HTTP 200", jr)), "[inspect] agent fetched https://127.0.0.1:8443 -> HTTP 200 THROUGH the terminating proxy")
    insp_after = n(count("inspect"), "CNT")
    check(insp_before >= 0 and insp_after > insp_before, f"[inspect] proxy signed a Hook=inspect record ({insp_before} -> {insp_after})")
    check("method=GET" in run(f"grep '\"hook\":\"inspect\"' {CHAIN} 2>/dev/null | tail -1"), "[inspect] inspect record carries method=GET (content was parsed)")
    va = run(f"bulkhead-collector verify-audit {CHAIN} 2>&1; echo VA=$?", t=30)
    check("VA=0" in va and "domain: egress-proxy" in va, "[inspect] egress chain still verifies signed (domain=egress-proxy)")

    # ===== ARM 2: passthrough — the SAME host re-marked, spliced OPAQUE =====
    pass_before = n(count("passthrough"), "CNT")
    insp_mid = n(count("inspect"), "CNT")
    set_proxy("passthrough")
    sout2, jr2 = run_agent("mitmpass")
    out("\n[passthrough agent journal]\n" + jr2)
    check("SRC=0" in sout2, "[passthrough] confined agent reached FINAL (exit 0)")
    check(bool(re.search(r"OK: fetch 127\.0\.0\.1:8443 -> HTTP 200", jr2)), "[passthrough] agent fetched 200 via opaque end-to-end TLS")
    pass_after = n(count("passthrough"), "CNT")
    check(pass_before >= 0 and pass_after > pass_before, f"[passthrough] proxy signed a Hook=passthrough record ({pass_before} -> {pass_after})")
    check(n(count("inspect"), "CNT") == insp_mid, "[passthrough] NO new Hook=inspect (flow was NOT body-inspected)")
    check("reason=default" in run(f"grep '\"hook\":\"passthrough\"' {CHAIN} 2>/dev/null | tail -1"), "[passthrough] passthrough record marks reason=default (uninspected, honest ledger)")

    # ===== ARM 3 (security-review R4): inspect, but the proxy CANNOT terminate this port. The host is
    #       marked `inspect`, yet 8443 is no longer in the TLS-port set, so the proxy cannot TLS-terminate
    #       + content-inspect it. It must FAIL CLOSED (deny) — NOT silently splice the host through
    #       uninspected (the old behaviour, which let a missing CA / wrong port downgrade inspect to
    #       passthrough). The deny is signed reason=inspect-unavailable; no inspect/passthrough is written. =====
    insp_b4 = n(count("inspect"), "CNT")
    pass_b4 = n(count("passthrough"), "CNT")
    set_proxy("inspect", tls_ports="9999")  # 8443 excluded -> the inspect host is non-terminable here
    check("active" in run("systemctl is-active bulkhead-egress-proxy.service 2>&1"), "[R4] proxy restarted: inspect host, but 8443 is NOT a TLS port (non-terminable)")
    sout4, jr4 = run_agent("mitmr4")
    out("\n[R4 inspect-unavailable agent journal]\n" + jr4)
    check(not re.search(r"OK: fetch 127\.0\.0\.1:8443 -> HTTP 200", jr4),
          "[R4] the agent did NOT get HTTP 200 — the inspect-but-unterminable host was REFUSED, not passed through")
    denyrec = run(f"grep 'inspect-unavailable' {CHAIN} 2>/dev/null | tail -1")
    check('"decision":"deny"' in denyrec and "dst=127.0.0.1:8443" in denyrec,
          "[R4] the chain signed a DENY (reason=inspect-unavailable) for the unterminable inspect host")
    check(n(count("inspect"), "CNT") == insp_b4 and n(count("passthrough"), "CNT") == pass_b4,
          "[R4] NO new inspect AND NO new passthrough record — the host was never spliced (fail CLOSED, not fail open)")
    va4 = run(f"bulkhead-collector verify-audit {CHAIN} 2>&1; echo VA=$?", t=30)
    check("VA=0" in va4 and "domain: egress-proxy" in va4, "[R4] egress chain still verifies signed after the fail-closed deny")

    # ===== ARM 4 (ADR-0034 inc2 sub-B): the BULKHEAD_EGRESS_DEFAULT_MODE=inspect knob. The allowlist
    #       entry is UNMARKED, but the default-mode knob makes it `inspect` — so the host is
    #       TLS-terminated + content-inspected exactly as an explicit `inspect` entry would be. This is
    #       the high-assurance "inspect everything (that can be terminated)" posture, the natural
    #       completion of R4 (which made an un-terminable inspect host fail closed). =====
    insp_b5 = n(count("inspect"), "CNT")
    set_proxy("", tls_ports="8443", default_mode="inspect")  # UNMARKED 127.0.0.1 + the knob
    check("active" in run("systemctl is-active bulkhead-egress-proxy.service 2>&1"), "[knob] proxy restarted: UNMARKED allowlist entry + BULKHEAD_EGRESS_DEFAULT_MODE=inspect")
    sout5, jr5 = run_agent("mitmknob")
    out("\n[knob agent journal]\n" + jr5)
    check("SRC=0" in sout5, "[knob] confined agent reached FINAL (exit 0)")
    check(bool(re.search(r"OK: fetch 127\.0\.0\.1:8443 -> HTTP 200", jr5)),
          "[knob] agent fetched 8443 -> HTTP 200 through the TERMINATING proxy — the knob made the UNMARKED host inspect")
    insp_a5 = n(count("inspect"), "CNT")
    check(insp_b5 >= 0 and insp_a5 > insp_b5,
          f"[knob] the unmarked host produced a Hook=inspect record ({insp_b5} -> {insp_a5}) — default-inspect is active, not passthrough")
    va5 = run(f"bulkhead-collector verify-audit {CHAIN} 2>&1; echo VA=$?", t=30)
    check("VA=0" in va5 and "domain: egress-proxy" in va5, "[knob] egress chain still verifies signed")

    run("systemctl stop mockchat-tls.service bulkhead-mockchat.service 2>&1; true")
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
