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
#
# ADR-0021 (posture self-attest GATE — load-bearing): the gate unit is active from cold boot + `attest
# gate` returns OK while E0+E2 armed + tcb_clean; tailscale-up Requires= the gate; NEGATIVE: soft-disarm
# -> gate fails closed fast -> the gate unit fails -> a Requires=-the-gate unit is refused; then re-arm
# restores a clean box. Makes a real action (the tailnet join) fail-closed on the live enforcing posture.
#
# ADR-0022 (reproducible expected-D): the expected digest D is DERIVED OFF-BOX via `attest expected-d
# <collector-binary>` (composeDigest over the known-good binary + the default-armed posture) and that
# off-box D drives every verify -- the journal grep is kept only as a cross-check. Breaks the journal-
# circularity (a tampered collector can no longer self-pass by logging a green D).
#
# ADR-0025 (bind audit-chain HEADs into the quote): the quote's ExtraData = quoteExtraData(verifier
# nonce || the three signed chains' HEADs reported in the envelope), so ONE quote gives a non-repudiable,
# replay-proof, TAMPER-EVIDENT commitment to the box's audit-chain state. `attest heads` reads the live
# HEADs (collHex:ctrlHex:brokerHex). Checks: heads well-formed; the broker chain file exists at the
# derived path (a genesis broker HEAD is an empty chain, not a mis-resolved path); the quote's REPORTED
# control HEAD == the live control HEAD (the box bound its real state — the high-rate provenance HEAD
# advances per enforcement decision so it is bound but not cross-checkable here); NEGATIVE 4 — verify
# FAILS CLOSED when a REPORTED head_*_hex is altered (the heads are non-repudiable). Honest seam: the
# quote makes the reported HEADs unforgeable+fresh; NO-REWIND vs a prior observation is a SEPARATE
# verify-audit step on the shipped logs (continuity + tip == bound HEAD + no regression).
#
# ADR-0026 (the no-rewind VERDICT): verify-audit gained --expect-tip (the verified log's tip must == a
# quote's reported+attested HEAD, joining the non-repudiable HEAD to the continuity proof) and --since
# (a prior-observed HEAD must be a VERIFIED ANCESTOR of the tip -> no-rewind CLEAN; a HEAD not in the
# chain -> REWOUND/FORKED, fail-closed). Checks: 26.1 the quote's control HEAD == the verify-audit tip;
# 26.2 --since a prior HEAD is CLEAN; 26.3 --since a HEAD not in the chain fails closed. Closes the loop
# ADR-0025 deferred: quote (unforgeable current HEAD) + verify-audit (continuity + ancestry) = no-rewind.
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
    # ADR-0022: the verifier DERIVES the expected digest D OFF-BOX from the known-good (byte-
    # reproducible) collector binary + the expected default-armed posture, via `attest expected-d` --
    # it NO LONGER sources D from the box's own `attest: extended` journal line (that grep is kept ONLY
    # as a cross-check). /usr/bin/bulkhead-collector == the running collector's /proc/self/exe on the RO
    # rootfs, so this is the on-box stand-in for a relying party's known-good binary (the host can run
    # the SAME static binary against the byte-reproduced artifact off-box).
    dx = run("bulkhead-collector attest expected-d /usr/bin/bulkhead-collector 2>/tmp/xd.err").strip()
    mx = re.search(r"\b([0-9a-f]{64})\b", dx)
    Dx = mx.group(1) if mx else ""
    aj = run("journalctl -u bulkhead-collector.service --no-pager 2>&1 | grep -a 'attest: extended' | tail -2")
    out("\n[expected-d off-box]\n" + dx + "\n[attest extend (collector journal, CROSS-CHECK only)]\n" + aj + "\n")
    mj = re.search(r"TCB digest ([0-9a-f]{64})", aj)
    Dj = mj.group(1) if mj else ""
    D = Dx  # the VERIFIER uses the OFF-BOX-derived D, not the journal
    check(is_active("bulkhead-attest.service") and Dx != "" and Dx == Dj,
          "ADR-0022: expected-D derived OFF-BOX (collector binary + default-armed posture) MATCHES the box's extended digest -> journal-circularity broken (verifier no longer trusts the box's own journal)")

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

    # ADR-0025: capture the box's three signed-chain HEADs (collector provenance, control, broker) as
    # collHex:ctrlHex:brokerHex — the relying party's prior-observation, for the no-rewind verify-audit
    # step and to cross-check the quote's REPORTED heads against the live logs. The collector unit sets
    # BULKHEAD_AUDIT_DIR; a bare shell does not, so pass the image's audit dir (the broker dir derives).
    hraw = run("BULKHEAD_AUDIT_DIR=/data/bulkhead/audit bulkhead-collector attest heads > /tmp/heads.txt 2>/tmp/heads.err; echo RC=$?")
    HEADS_OUT = run("cat /tmp/heads.txt")
    mh = re.search(r"([0-9a-f]{64}):([0-9a-f]{64}):([0-9a-f]{64})", HEADS_OUT)
    h_ctrl = mh.group(2) if mh else ""
    out("\n[attest heads]\n" + HEADS_OUT + "\n")
    check("RC=0" in hraw and mh is not None,
          "ADR-0025: attest heads read the three signed-chain HEADs as collHex:ctrlHex:brokerHex (the prior-observation capture + the live-log cross-check source)")

    # ADR-0025 path-correctness: the broker chain is genesis (HEAD 0*64) until the first delegation, so a
    # zero broker HEAD here is EXPECTED. Assert the broker's provenance.jsonl EXISTS at the derived
    # brokerAuditDir (<base>-broker) — the broker creates it at startup (openAuditLog MkdirAll+O_CREATE) —
    # so a genesis broker HEAD is a real EMPTY chain, NOT a silently mis-resolved path binding zeros (the
    # collector binds the SAME derived path, so a wrong path would bind nothing for the broker undetected).
    bex = run("test -f /data/bulkhead/audit-broker/provenance.jsonl; echo RC=$?")
    check("RC=0" in bex,
          "ADR-0025: the broker chain file exists at the derived brokerAuditDir (a genesis broker HEAD is an empty chain, not a mis-resolved path)")

    # ADR-0025 live-log cross-check: the quote REPORTS the heads it bound (envelope head_*_hex). The
    # control chain is stable in this agent-less window (it advances only on operator/agent authority
    # ops), so the quote's reported control head must equal the independently-read live control head —
    # proving the box reported its REAL chain state, not a fabricated one. (The collector PROVENANCE head
    # advances on every enforcement decision, so it is bound non-repudiably but NOT cross-checkable here.)
    ce = run("grep -o '\"head_control_hex\":\"[0-9a-f]*\"' /tmp/env.json")
    mce = re.search(r"head_control_hex\":\"([0-9a-f]{64})", ce)
    env_ctrl = mce.group(1) if mce else ""
    check(env_ctrl != "" and env_ctrl == h_ctrl,
          "ADR-0025: the quote's REPORTED control HEAD == the live control chain HEAD (the box bound its real chain state, not a fabricated one)")

    # POSITIVE verify: genuine quote, fresh nonce, PINNED-AK sig, the ExtraData commits to the reported
    # chain HEADs (non-repudiable + tamper-evident), PCR-14 selection, PCR == H(0^32||D).
    v = run(f"bulkhead-collector attest verify /tmp/env.json {D} {nonce} @/tmp/box-ak.hex 2>&1; echo RC=$?")
    out("\n[verify+]\n" + v + "\n")
    check("attest verify: OK" in v and "RC=0" in v,
          "attest verify OK — a relying party can PROVE the enforcing-TCB state + a non-repudiable, tamper-evident commitment to the audit-chain HEADs (pinned AK + fresh nonce + PCR-14 selection + PCR match)")

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

    # NEGATIVE 4 — TAMPER-EVIDENT HEADS (ADR-0025): alter a REPORTED chain HEAD in the envelope
    # (head_collector_hex, first nibble flipped) but leave the TPM-signed quote intact. The verifier
    # recomputes the ExtraData over the (now-altered) reported heads, which no longer matches the quote's
    # signed ExtraData -> FAIL CLOSED. Proves the reported heads are non-repudiable: a MITM/box cannot
    # restate the audit-chain heads a quote committed to. (No-rewind vs a prior obs is verify-audit's job.)
    # The guest is a minimal image with NO python3 — extract the reported head here (host) and apply the
    # flip with guest sed (busybox). The 64-hex head is unique in the one-line envelope, so the exact-
    # string substitution hits only that field.
    cc = run("grep -o '\"head_collector_hex\":\"[0-9a-f]*\"' /tmp/env.json")
    mcc = re.search(r"head_collector_hex\":\"([0-9a-f]{64})", cc)
    h_coll = mcc.group(1) if mcc else ""
    bad_coll = ("1" if h_coll[:1] != "1" else "0") + h_coll[1:]
    sed = run(f"sed 's/{h_coll}/{bad_coll}/' /tmp/env.json > /tmp/env-badhead.json; "
              f"test \"$(cat /tmp/env-badhead.json)\" != \"$(cat /tmp/env.json)\"; echo RC=$?")
    v5 = run(f"bulkhead-collector attest verify /tmp/env-badhead.json {D} {nonce} @/tmp/box-ak.hex 2>&1; echo RC=$?")
    out("\n[verify- tampered reported head]\n" + v5 + "\n")
    check(h_coll != "" and "RC=0" in sed and "RC=0" not in v5 and "FAIL" in v5,
          "tamper-evident HEADs: verify FAILS when a REPORTED chain HEAD is altered (the quote's ExtraData non-repudiably commits to the heads; they cannot be restated)")

    # ===== ADR-0026: the NO-REWIND VERDICT (verify-audit ties the quote's HEAD to a continuity-verified
    # log + proves a prior observation is an ancestor) — closing the loop ADR-0025 deferred =====
    CTLCHAIN = "/data/bulkhead/audit/control.jsonl"  # resolves the sibling audit-pub.txt; domain=control
    # 26.1 END-TO-END TIE: the verified control log's tip == the quote's REPORTED+attested control HEAD,
    # so this continuity-verified chain IS the one the quote committed to (joins the non-repudiable HEAD
    # from `attest verify` to the hash-chain integrity proof). Exit 0 + "tip == the quote-bound HEAD".
    e2e = run(f"bulkhead-collector verify-audit {CTLCHAIN} --expect-tip={env_ctrl} 2>&1; echo RC=$?")
    out("\n[ADR-0026 expect-tip]\n" + e2e + "\n")
    check("RC=0" in e2e and "tip == the quote-bound HEAD" in e2e and "verify-audit: OK" in e2e,
          "ADR-0026: verify-audit ties the quote's attested control HEAD to the continuity-verified log (tip == the quote-bound HEAD)")

    # 26.2 ANCESTRY CLEAN: a prior-observed HEAD (here the current control tip, captured live) is a
    # verified ANCESTOR of the tip -> no-rewind CLEAN, exit 0. (h_ctrl == the tip now; the advanced-
    # ancestor case is unit-tested in verify_test.go where seq>1 records sit above the observation.)
    clean = run(f"bulkhead-collector verify-audit {CTLCHAIN} --since={h_ctrl} 2>&1; echo RC=$?")
    out("\n[ADR-0026 since CLEAN]\n" + clean + "\n")
    check("RC=0" in clean and "no-rewind CLEAN" in clean,
          "ADR-0026: verify-audit --since a prior-observed HEAD renders no-rewind CLEAN (the chain extends the observation)")

    # 26.3 REWIND/FORK DETECTED: a prior HEAD that is NOT in the chain (a fork that dropped it, or a
    # rewind below it) cannot reproduce its hash -> REWOUND/FORKED, fail-closed exit 1.
    bogus_head = "de" + "0" * 62
    rew = run(f"bulkhead-collector verify-audit {CTLCHAIN} --since={bogus_head} 2>&1; echo RC=$?")
    out("\n[ADR-0026 since REWOUND]\n" + rew + "\n")
    check("RC=0" not in rew and "REWOUND/FORKED" in rew,
          "ADR-0026: verify-audit --since a HEAD NOT in the chain FAILS CLOSED as REWOUND/FORKED (the no-rewind teeth)")

    # 26.4 FAIL-OPEN GUARD (adversarial-review fix): a misspelled flag (--sinc=) must NOT be silently
    # dropped into the pubkey positional and ignored — that would skip a REQUESTED no-rewind check yet
    # exit 0 (false assurance). It must fail CLOSED with "unknown flag".
    typo = run(f"bulkhead-collector verify-audit {CTLCHAIN} --sinc={h_ctrl} 2>&1; echo RC=$?")
    out("\n[ADR-0026 typo-flag]\n" + typo + "\n")
    check("RC=0" not in typo and "unknown flag" in typo,
          "ADR-0026: a misspelled flag fails CLOSED (unknown flag), never silently skipping a requested no-rewind check")

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

    # ===== ADR-0021: posture self-attest GATE — make attestation LOAD-BEARING =====
    # POSITIVE: the gate unit RAN on cold boot (not Condition-skipped by the socket-bind race -> proves
    # the binary-Condition + controlRPCGate retry choice) AND passed -> the exactly-{E0,E2} predicate
    # does NOT self-brick a healthy hardened boot.
    check(is_active("bulkhead-attest-gate.service"),
          "posture gate active from cold boot (the {E0,E2}+tcb_clean predicate does not self-brick a healthy armed boot)")
    g = run("bulkhead-collector attest gate 2>&1; echo RC=$?")
    out("\n[gate+]\n" + g + "\n")
    check("RC=0" in g and "OK" in g and "e0=1" in g and "e2=1" in g and "tcb_clean=true" in g,
          "attest gate OK while armed (the collector TCB read E0=1 E2=1 tcb_clean live from the pinned maps)")

    # LOAD-BEARING WIRING (static): the tailnet join HARD-depends (Requires=) on the gate. The harness
    # has no /mnt/tsauth/authkey so tailscale-up itself is Condition-skipped, hence we assert the
    # dependency edge + the gate's own pass/fail rather than an actual join.
    req = run("systemctl show tailscale-up.service -p Requires -p After 2>&1")
    out("\n[tailscale-up deps]\n" + req + "\n")
    check("bulkhead-attest-gate.service" in req,
          "tailscale-up Requires=+After= the gate (the tailnet join is mechanically coupled to live enforcement state)")

    # NEGATIVE: soft-disarm E0 (the proven routed lever) -> the gate FAILS CLOSED FAST (no 30s hang).
    run("systemctl stop bulkhead-enforce.service 2>&1; echo done", t=30)
    run("sleep 1 2>/dev/null; true")
    g2 = run("bulkhead-collector attest gate 2>&1; echo RC=$?")
    out("\n[gate- disarmed]\n" + g2 + "\n")
    check("RC=0" not in g2 and "not-armed" in g2 and "e0=0" in g2,
          "disarmed: attest gate FAILS CLOSED fast (e0=0 -> not-armed, immediate server ERR, no boot-race hang)")
    # the gate unit itself fails when re-evaluated disarmed -> any Requires= dependent is refused.
    run("systemctl restart bulkhead-attest-gate.service 2>&1; echo done", t=30)
    check(not is_active("bulkhead-attest-gate.service"),
          "gate unit FAILS (inactive) when disarmed -> its Requires= dependents (tailscale-up) are refused")
    # DIRECT dynamic proof (if systemd-run is present): a transient unit that Requires= the gate cannot
    # start while the box is disarmed.
    if "RC=0" in run("command -v systemd-run >/dev/null 2>&1; echo RC=$?"):
        tr = run("systemd-run --wait --quiet --unit=bh-gate-probe --property=Requires=bulkhead-attest-gate.service --property=After=bulkhead-attest-gate.service /bin/true 2>&1; echo RC=$?")
        out("\n[gated transient]\n" + tr + "\n")
        run("systemctl reset-failed bh-gate-probe.service 2>/dev/null; true")
        check("RC=0" not in tr,
              "a unit that Requires= the gate is REFUSED to start while disarmed (the load-bearing block, demonstrated directly)")

    # RE-ARM -> leave a CLEAN, gate-passing box (graceful poweroff; the break-glass re-arm path works).
    run("systemctl start bulkhead-enforce-egress.service bulkhead-enforce.service 2>&1; echo done", t=30)
    run("sleep 1 2>/dev/null; true")
    g3 = run("bulkhead-collector attest gate 2>&1; echo RC=$?")
    out("\n[gate+ re-armed]\n" + g3 + "\n")
    run("systemctl restart bulkhead-attest-gate.service 2>&1; echo done", t=30)
    check("RC=0" in g3 and "e0=1" in g3 and is_active("bulkhead-attest-gate.service"),
          "re-arm (break-glass) restored: gate passes again + unit active (clean armed box for poweroff)")

    # MASK regression (ADR-0021 review fix): a MASKED Requires= is a hard "is masked" failure, NOT a
    # vacuous-satisfy -> masking the gate REFUSES a Requires= dependent (so masking bricks the rejoin;
    # re-arm is the supported break-glass, per the corrected deploy/tailscale-join.md). Unmask -> clean.
    # MASK regression (ADR-0021 review fix): on the SHIPPED systemd (verified 255.21), masking the gate
    # makes the REAL file-based Requires= dependent FAIL ("A dependency job for tailscale-up.service
    # failed") -> masking BRICKS the rejoin, so re-arm is the supported break-glass (the corrected
    # deploy/tailscale-join.md). Stop+mask so the edge hits the mask (not a still-active instance), test
    # the actual tailscale-up.service (a systemd-run --property=Requires= transient does NOT replicate
    # file-based Requires= masking on 255), then restore a clean armed box.
    # NOTE: `systemctl mask` (persistent) FAILS on the RO rootfs (it can't overwrite the installed
    # unit at /etc/systemd/system) -> use `mask --runtime` which masks in /run (tmpfs, writable, and
    # /run OVERRIDES /etc), so the mask actually applies and the masked Requires= fails the join FAST
    # at transaction build (no ExecStart -> no hang). `timeout 20` is a belt-and-suspenders so a future
    # wiring change can never hang the harness on a blocking `systemctl start`.
    run("systemctl stop bulkhead-attest-gate.service 2>&1; echo done", t=30)
    run("systemctl mask --runtime bulkhead-attest-gate.service 2>&1; echo done", t=30)
    tsmk = run("systemctl start tailscale-up.service 2>&1; echo RC=$?", t=40)
    out("\n[masked gate -> tailscale-up start]\n" + tsmk + "\n")
    run("systemctl reset-failed tailscale-up.service 2>/dev/null; true")
    run("systemctl unmask --runtime bulkhead-attest-gate.service 2>&1; echo done", t=30)
    run("systemctl start bulkhead-attest-gate.service 2>&1; echo done", t=30)  # restore active + clean
    check("RC=0" not in tsmk and ("dependency" in tsmk.lower() or "masked" in tsmk.lower()),
          "masked gate FAILS the real tailscale-up Requires= ('dependency job failed') -> masking BRICKS rejoin; re-arm is the supported break-glass (doc claim corrected + regression-guarded on systemd 255)")
    check(is_active("bulkhead-attest-gate.service"),
          "mask probe left the gate active again (clean armed box for poweroff)")

    # ===== ADR-0023: on-box CRYPTOGRAPHIC self-check GATE (augment the map-read gate with a TPM proof) =====
    # The box produces a FRESH-NONCE quote under its AK and runs the five `attest verify` checks against
    # the expected DEFAULT-ARMED D it derives from its OWN /proc/self/exe — all in the collector (TCB).
    # On this swtpm harness no /data pin is provisioned, so it runs the STRUCTURAL FALLBACK (self-akpub:
    # genuine-TPM + fresh + PCR-match, NO identity assertion). The box must be ARMED here (re-armed above).
    #
    # POSITIVE: the second gate unit RAN on cold boot (its /dev/tpmrm0 Condition is satisfied — a TPM is
    # attached) AND the live selfcheck passes against the boot-extended PCR.
    check(is_active("bulkhead-attest-selfcheck-gate.service"),
          "ADR-0023: crypto self-check gate active from cold boot (TPM present -> Condition satisfied; fresh-nonce quote verified the boot-extended PCR == expected default-armed D)")
    sc = run("bulkhead-collector attest selfcheck 2>&1; echo RC=$?")
    out("\n[selfcheck+ structural-fallback]\n" + sc + "\n")
    check("RC=0" in sc and "OK" in sc and "structural-fallback" in sc and ("PCR 14" in sc or "PCR %d" % 14 in sc),
          "ADR-0023 POSITIVE: attest selfcheck OK on the armed box (fresh-nonce quote verifies, PCR 14 == expected default-armed D, self-akpub structural fallback — no pre-provisioned pin on this harness, so NO identity/genuine-TPM claim)")

    # S4 (review fix): a collector/attest restart must NOT double-extend the immutable PCR 14 (a re-
    # extend would corrupt it to H(H(0||D)||D) -> selfcheck (e) fails -> the hard Requires= would
    # permanently brick the rejoin until reboot). `attest extend` is idempotent (PCR_Read + skip), so
    # re-running it leaves the PCR intact and the self-check still PASSES.
    run("systemctl restart bulkhead-attest.service 2>&1; echo done", t=30)
    sci = run("bulkhead-collector attest selfcheck 2>&1; echo RC=$?")
    out("\n[selfcheck after attest restart (idempotent extend)]\n" + sci + "\n")
    check("RC=0" in sci and "OK" in sci,
          "ADR-0023 S4: re-running `attest extend` (unit restart) is IDEMPOTENT -> PCR 14 not double-extended, selfcheck still PASSES (no permanent crypto-gate brick on a collector/attest restart)")

    # NEGATIVE (induce a crypto-gate FAIL WITHOUT a non-enforcing boot): drop a WRONG pre-provisioned
    # EK-rooted pin so the box switches off the structural fallback into the IDENTITY path, where the
    # quote's genuine AK must bytewise-match the (wrong) pin -> FAIL. /data is the persistent pin home;
    # if it is not writable on this harness we fall back to skipping (the pin path is still unit-tested).
    PIN = "/data/bulkhead/attest-ak.pin"
    wr = run(f"mkdir -p /data/bulkhead 2>/dev/null && printf '%s\\n' {WRONG_AK} > {PIN} 2>/dev/null && test -s {PIN}; echo RC=$?")
    if "RC=0" in wr:
        scn = run(f"bulkhead-collector attest selfcheck 2>&1; echo RC=$?")
        out("\n[selfcheck- wrong pre-provisioned pin]\n" + scn + "\n")
        run(f"rm -f {PIN} 2>/dev/null; true")  # restore the structural-fallback (clean) state
        check("RC=0" not in scn and "FAIL" in scn and "pin" in scn.lower(),
              "ADR-0023 NEGATIVE: a WRONG pre-provisioned EK-rooted pin makes selfcheck FAIL CLOSED on the AK identity mismatch (the box won't self-pass with a forged identity) — induced without a non-enforcing boot")
        # and it is back to passing once the bad pin is removed (no permanent brick)
        scr = run("bulkhead-collector attest selfcheck 2>&1; echo RC=$?")
        check("RC=0" in scr and "OK" in scr,
              "ADR-0023: removing the bad pin restores the structural-fallback PASS (the wrong-pin FAIL was not a brick)")
    else:
        out(f"\n[selfcheck- pin negative SKIPPED: {PIN} not writable on this harness]\n")

    # LOAD-BEARING WIRING (static, AUGMENT not REPLACE): tailscale-up Requires=+After= BOTH gates — the
    # unconditional ADR-0021 map-read gate AND this /dev/tpmrm0-conditioned crypto gate.
    req2 = run("systemctl show tailscale-up.service -p Requires -p After 2>&1")
    out("\n[tailscale-up deps (both gates)]\n" + req2 + "\n")
    check("bulkhead-attest-gate.service" in req2 and "bulkhead-attest-selfcheck-gate.service" in req2,
          "ADR-0023 WIRING: tailscale-up Requires= BOTH the map-read gate (unconditional) AND the crypto self-check gate (augment, never replace) -> the join is coupled to a TPM-signed proof, layered on the live map read")
    # the crypto gate conditions on the TPM (so a no-TPM box skips it, gated only by the map read); the
    # map-read gate does NOT (so a no-TPM enforcing box is still gated, never bricked).
    # systemctl show -p Conditions serializes as "[unprintable]", so read the Condition from the
    # installed unit files: the crypto gate is conditioned on /dev/tpmrm0 (skips no-TPM), the map-read
    # gate is NOT (conditioned on the collector binary, so it still gates a no-TPM enforcing box).
    cond_sc = run("systemctl cat bulkhead-attest-selfcheck-gate.service 2>&1 | grep ConditionPathExists")
    cond_mr = run("systemctl cat bulkhead-attest-gate.service 2>&1 | grep ConditionPathExists")
    out("\n[selfcheck-gate Condition]\n" + cond_sc + "\n[map-read-gate Condition]\n" + cond_mr + "\n")
    check("/dev/tpmrm0" in cond_sc and "/dev/tpmrm0" not in cond_mr,
          "ADR-0023 NO-TPM DEGRADE (never-brick): the crypto gate ConditionPathExists=/dev/tpmrm0 (skips on a TPM-less box) while the map-read gate does NOT -> a no-TPM enforcing box is still gated by the map read, not fail-open and not bricked")

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
