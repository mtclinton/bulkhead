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
# genuine TPM quote; (3) the box AK pub is captured TOFU as the out-of-band PIN (`attest akpub`);
# (4) `attest verify` against the PINNED AK PASSES (measured digest + fresh nonce + PCR-14 selection);
# (5) NEGATIVE — verify FAILS CLOSED against a TAMPERED expected digest; (6) NEGATIVE — verify FAILS
# against a DIFFERENT nonce (no replay); (7) NEGATIVE — verify FAILS against a WRONG/different AK pub
# (the AK-pinning fix: a forged or other-box envelope is rejected by the pin).
#
# ADR-0020 (EK-cert credential-activation — ROOT the AK in the TPM EK): (8) `attest ek` enrollment, the
# enrolled AK == the quote AK; (9) off-box `attest make-credential` wraps a fresh secret to the EK + AK
# Name; (10) on-box `attest activate` recovers it -> `attest enroll-verify` OK -> EK-rooted pin; (11)
# that pin is drop-in for the quote verify. NEGATIVES: N1 fabricated EK (foreign EK can't decrypt ->
# activate fails), N2 wrong-AK-Name (loaded AK's Name != wrapped -> RC_INTEGRITY), N3 forged request
# (verifier rejects claimed ak_name != recomputed Name). Honest seam: swtpm EK cert is self-signed dev
# PKI, so this proves the credential-activation MECHANISM + EK-binding, not silicon-genuineness.
import pexpect, sys, os, re, secrets
RUN = "/home/work/ideas/bulkhead/yocto/scripts/run-qemu-tpm.sh"
# A DIFFERENT, VALID P-256 PKIX-DER pubkey (generated off-box) — the "wrong box" AK for the
# cross-AK negative: resolveAKPin parses it fine, so verify must reject it on the bytewise PIN
# mismatch (not a parse error), proving the pin actually binds box identity.
WRONG_AK = "3059301306072a8648ce3d020106082a8648ce3d03010703420004a31ccc87687be8350847c12667dea49ebb1114a731c0fcc6aa85627cc1926f8e31d6d5a628d6ce19ee92160b87ca831a17a35a50d969ff28957e8b9bcce76841"
# ADR-0020 EK-rooting negatives (generated off-box, all VALID structures so the failures are on the
# crypto binding, not parse errors): a fabricated EK pub_tpmt (a foreign EK the genuine TPM can't
# decrypt to), and a self-consistent WRONG AK triple (tpmt/der/name agree, so the verifier's binding
# checks pass — the failure is the loaded AK's Name != the wrapped Name, i.e. RC_INTEGRITY on-box).
WRONG_EK_TPMT = "0023000b000300b20020837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa000600800043001000030010002081cb7c87330b4c124fb9455097ad891eb4411dd8860956a3a3f1a18a73531aa80020a5b1b63d552c3c2d383a1f91c65dec1d41c63cadf2a008516fbec2d956c6206a"
WRONG_AK_TPMT = "0023000b000300b20020837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa0006008000430010000300100020d7fcbebcf4d429a76a64067c72653f840e70caa3ceccd569a2014a70cb1033150020611840d16a53aacc61a586a65caf8bae0168b66eb234354969fad5c11561312c"
WRONG_AK_NAME = "000bad78a49eb5fe3555b6045882dd88166e531cd5152de2964f6efbc1b2520afa2a"
WRONG_AK_DER = "3059301306072a8648ce3d020106082a8648ce3d03010703420004d7fcbebcf4d429a76a64067c72653f840e70caa3ceccd569a2014a70cb103315611840d16a53aacc61a586a65caf8bae0168b66eb234354969fad5c11561312c"
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
    # the COLLECTOR (TCB) does the extend in-process and logs the digest to ITS journal; the attest
    # unit's own journal just carries the CLI's "OK <digest>". Read D from the collector journal.
    aj = run("journalctl -u bulkhead-collector.service --no-pager 2>&1 | grep -a 'attest: extended' | tail -2")
    out("\n[attest extend (collector journal)]\n" + aj + "\n")
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

    # TOFU: capture the box's AK pub as the PIN (a relying party records this on first contact). The
    # pin is what binds the proof to THIS box — without it any genuine TPM could forge a PASS.
    ak = run("bulkhead-collector attest akpub /tmp/env.json > /tmp/box-ak.hex 2>/tmp/ak.err; echo RC=$?")
    check("RC=0" in ak and "RC=0" in run("test -s /tmp/box-ak.hex; echo RC=$?"),
          "attest akpub captured the box AK pub (the out-of-band TOFU pin)")

    # POSITIVE verify: genuine quote, fresh nonce, PINNED-AK sig, PCR-14 selection, PCR == H(0^32||D).
    v = run(f"bulkhead-collector attest verify /tmp/env.json {D} {nonce} @/tmp/box-ak.hex 2>&1; echo RC=$?")
    out("\n[verify+]\n" + v + "\n")
    check("attest verify: OK" in v and "RC=0" in v,
          "attest verify OK — a relying party can PROVE the enforcing-TCB state (pinned AK + fresh nonce + PCR-14 selection + PCR match)")

    # NEGATIVE 1 — TAMPER: a different expected digest (one byte flipped), correct pin, must FAIL CLOSED.
    badD = ("0" if D[0] != "0" else "1") + D[1:]
    v2 = run(f"bulkhead-collector attest verify /tmp/env.json {badD} {nonce} @/tmp/box-ak.hex 2>&1; echo RC=$?")
    out("\n[verify- tamper]\n" + v2 + "\n")
    check("RC=0" not in v2 and "FAIL" in v2,
          "tamper rejected: verify FAILS CLOSED against a different expected digest (a box not in the expected state cannot pass)")

    # NEGATIVE 2 — REPLAY: a different nonce than the quote was bound to, correct pin, must FAIL.
    other = secrets.token_hex(32)
    v3 = run(f"bulkhead-collector attest verify /tmp/env.json {D} {other} @/tmp/box-ak.hex 2>&1; echo RC=$?")
    out("\n[verify- replay]\n" + v3 + "\n")
    check("RC=0" not in v3 and "FAIL" in v3,
          "replay rejected: verify FAILS against a nonce the quote was not bound to (no stale-quote replay)")

    # NEGATIVE 3 — WRONG AK (the AK-pinning fix): a genuine quote but pinned to a DIFFERENT box's AK
    # must FAIL on the pin mismatch. This is the regression test for the forge where any other real
    # TPM (or a software key) could otherwise pass for the expected box.
    run(f"printf '%s' {WRONG_AK} > /tmp/wrong-ak.hex")
    v4 = run(f"bulkhead-collector attest verify /tmp/env.json {D} {nonce} @/tmp/wrong-ak.hex 2>&1; echo RC=$?")
    out("\n[verify- wrong-ak]\n" + v4 + "\n")
    check("RC=0" not in v4 and "FAIL" in v4 and "pinned" in v4.lower(),
          "wrong-AK rejected: verify FAILS on the AK pin (a forged/other-box envelope cannot pass for the expected box)")

    # ===== ADR-0020: EK-cert credential-activation — ROOT the AK in the TPM EK =====
    # POSITIVE 8: the enrollment request; the enrolled AK IS the quote AK (continuity). `attest akpub`
    # reads the ak_pub_der field present in BOTH the envelope and the enrollRequest.
    ek = run("bulkhead-collector attest ek > /tmp/ereq.json 2>/tmp/ek.err; echo RC=$?")
    out("\n[attest ek err]\n" + run("cat /tmp/ek.err 2>&1") + "\n")
    same = run('test "$(bulkhead-collector attest akpub /tmp/ereq.json 2>/dev/null)" = "$(cat /tmp/box-ak.hex)"; echo RC=$?')
    check("RC=0" in ek and "RC=0" in same,
          "attest ek: enrollment request produced; the enrolled AK == the quote AK (EK-rooting binds the same identity the quote uses)")

    # POSITIVE 9: off-box MakeCredential (no TPM) — a fresh secret wrapped to the EK + AK Name; the
    # round-state (secret + the recomputed bound AK key) is the verifier's private state enroll-verify
    # consumes (no re-suppliable request in the trust path -> can't pin a different key than proven).
    mc = run("bulkhead-collector attest make-credential /tmp/ereq.json /tmp/eround.json > /tmp/echal.json 2>/tmp/mc.err; echo RC=$?")
    check("RC=0" in mc and "RC=0" in run("test -s /tmp/echal.json && test -s /tmp/eround.json; echo RC=$?"),
          "attest make-credential: verifier wrapped a fresh secret to the EK + AK Name (CreateCredential, no TPM)")

    # POSITIVE 10: on-box ActivateCredential recovers it -> enroll-verify (round-state only) OK -> pin.
    act = run("bulkhead-collector attest activate /tmp/echal.json > /tmp/eresp.json 2>/tmp/act.err; echo RC=$?")
    out("\n[activate err]\n" + run("cat /tmp/act.err 2>&1") + "\n")
    ev = run("bulkhead-collector attest enroll-verify /tmp/eresp.json /tmp/eround.json /tmp/ek-pin.hex 2>&1; echo RC=$?")
    out("\n[enroll-verify]\n" + ev + "\n")
    check("RC=0" in act and "enroll-verify: OK" in ev and "RC=0" in ev,
          "EK-rooting loop closes: ActivateCredential recovered the secret -> AK is EK-rooted (loaded in the genuine TPM that owns the EK)")

    # POSITIVE 11: the EK-rooted pin is drop-in for the ADR-0019 quote verify.
    ekv = run(f"bulkhead-collector attest verify /tmp/env.json {D} {nonce} @/tmp/ek-pin.hex 2>&1; echo RC=$?")
    out("\n[verify+ ek-rooted pin]\n" + ekv + "\n")
    check("attest verify: OK" in ekv and "RC=0" in ekv,
          "the EK-rooted pin drives the existing quote verify to OK (drop-in: EK-rooted pin == the box AK pin)")

    # NEGATIVE N1 — FABRICATED EK: wrap to a foreign EK; the genuine TPM's EK cannot decrypt it.
    run(f"sed 's/\"ek_pub_tpmt\":\"[0-9a-f]*\"/\"ek_pub_tpmt\":\"{WRONG_EK_TPMT}\"/' /tmp/ereq.json > /tmp/req-badek.json")
    run("bulkhead-collector attest make-credential /tmp/req-badek.json /tmp/s-badek.hex > /tmp/chal-badek.json 2>/tmp/mcbadek.err")
    n1 = run("bulkhead-collector attest activate /tmp/chal-badek.json > /tmp/resp-badek.json 2>/tmp/actbadek.err; echo RC=$?")
    out("\n[N1 fabricated-EK activate err]\n" + run("cat /tmp/actbadek.err 2>&1") + "\n")
    check("RC=0" not in n1,
          "fabricated-EK rejected: ActivateCredential FAILS for a secret wrapped to a foreign EK (the secret returns ONLY from the genuine EK)")

    # NEGATIVE N2 — WRONG AK NAME: wrap to a self-consistent DIFFERENT AK (real EK); the loaded AK's
    # Name != the wrapped Name -> TPM_RC_INTEGRITY. (Keeps ek_pub_tpmt real; swaps the 3 AK fields.)
    run(f"sed 's/\"ak_pub_tpmt\":\"[0-9a-f]*\"/\"ak_pub_tpmt\":\"{WRONG_AK_TPMT}\"/; s/\"ak_pub_der\":\"[0-9a-f]*\"/\"ak_pub_der\":\"{WRONG_AK_DER}\"/; s/\"ak_name\":\"[0-9a-f]*\"/\"ak_name\":\"{WRONG_AK_NAME}\"/' /tmp/ereq.json > /tmp/req-badak.json")
    run("bulkhead-collector attest make-credential /tmp/req-badak.json /tmp/s-badak.hex > /tmp/chal-badak.json 2>/tmp/mcbadak.err")
    n2 = run("bulkhead-collector attest activate /tmp/chal-badak.json > /tmp/resp-badak.json 2>/tmp/actbadak.err; echo RC=$?")
    out("\n[N2 wrong-AK-name activate err]\n" + run("cat /tmp/actbadak.err 2>&1") + "\n")
    check("RC=0" not in n2,
          "wrong-AK-Name rejected: ActivateCredential FAILS when the wrapped Name != the loaded AK (binding to the SPECIFIC AK)")

    # NEGATIVE N3 — verifier rejects a forged request (claimed ak_name != recomputed Name of ak_pub_tpmt).
    run(f"sed 's/\"ak_name\":\"[0-9a-f]*\"/\"ak_name\":\"{WRONG_AK_NAME}\"/' /tmp/ereq.json > /tmp/req-forged.json")
    n3 = run("bulkhead-collector attest make-credential /tmp/req-forged.json /tmp/s-forged.hex 2>&1; echo RC=$?")
    out("\n[N3 forged-request make-credential]\n" + n3 + "\n")
    check("RC=0" not in n3 and "ak_name" in n3.lower(),
          "forged-request rejected: make-credential FAILS when claimed ak_name != recomputed Name of ak_pub_tpmt (verifier never trusts the claimed Name)")

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
